------------------------- MODULE CallLifecycle -------------------------
(* client/rpcclient agent-to-agent calls at their target: which frame
   starts a handler call, and what the target keeps of a call once its
   handler returned (spec/README.md "CallLifecycle.tla" is the design and
   maps each action to Go).

   The caller sends a call's request frames in order: data frames, its
   request end (CloseSend: an empty EOM) and, when it leaves, a cancel. A
   data frame that is not the call's first carries continuation = TRUE
   (TunnelFrame.continuation). The frames reach the target's receive loop
   in order (one FIFO: the caller's connection, the relay, the target's
   connection). The target keeps an entry per call it serves (incoming);
   its handler may return at any time (Return), before or after the
   caller's last frame, and its entry goes with it. A frame of a
   transaction the target has no entry for starts a call (or is refused at
   the start) only when it is a data frame without continuation; every
   other one is dropped. So the target keeps nothing for a call that ended
   or was refused (NoEndedEntry) and runs at most one handler call per
   transaction (AtMostOneCall).

   Mutants (scripts/spec.sh mutants): "late-new-call" (any data frame of an
   unknown transaction starts a call: the code before lane CONFORM6-RELAY),
   "old-caller" (callers that do not mark continuation frames: relay/client
   before lane CONFORM6-RELAY), "tombstone" (an ended call keeps its entry
   so its later frames are dropped: the fix that pulls against
   NoEndedEntry), "refused-first-kept" (a call refused at its start keeps
   its entry: the code before, for a first frame past the call's window),
   "drop-unknown" (every frame of an unknown transaction is dropped:
   AllServed), "retry-runs-again" (an E2EE retry of a call that ran starts
   it again: AtMostOneCall), "cancel-unreached" (a caller that leaves
   before any frame of its call went sends a cancel all the same: the code
   before lane A2AFINAL, for a call refused at the caller, a revoked key
   say: CancelKnown). *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Txns,    \* the calls' transaction ids
    N,       \* data frames each caller may send
    Retries, \* the calls whose caller may retry (an E2EE resume answered unknown)
    Mutant

ASSUME N >= 1

VARIABLES sent, closed, cancelled, retried, net, incoming, running, calls, refused, late
vars == <<sent, closed, cancelled, retried, net, incoming, running, calls, refused, late>>
caller == <<sent, closed, cancelled, retried>>
target == <<incoming, running, calls, refused, late>>

Frame == [t : Txns, kind : {"data", "eom", "cancel"}, cont : BOOLEAN, retry : BOOLEAN]

TypeOK ==
    /\ sent \in [Txns -> 0..N] /\ closed \in [Txns -> BOOLEAN]
    /\ cancelled \in [Txns -> BOOLEAN] /\ retried \in [Txns -> BOOLEAN]
    /\ \A i \in 1..Len(net) : net[i] \in Frame
    /\ incoming \subseteq Txns /\ running \subseteq Txns
    /\ calls \in [Txns -> 0..N] /\ refused \subseteq Txns /\ late \in BOOLEAN

Init ==
    /\ sent = [t \in Txns |-> 0]
    /\ closed = [t \in Txns |-> FALSE]
    /\ cancelled = [t \in Txns |-> FALSE]
    /\ retried = [t \in Txns |-> FALSE]
    /\ net = <<>>
    /\ incoming = {} /\ running = {}
    /\ calls = [t \in Txns |-> 0]
    /\ refused = {}
    /\ late = FALSE

\* clientStream.Send -> sendMsg: every data frame after the first is a
\* continuation (an old caller marks none). A Send that took its credit
\* before the caller left may follow its cancel.
Send(t) ==
    /\ sent[t] < N /\ ~closed[t]
    /\ sent' = [sent EXCEPT ![t] = @ + 1]
    /\ net' = Append(net, [t |-> t, kind |-> "data",
                           cont |-> sent[t] > 0 /\ Mutant # "old-caller", retry |-> FALSE])
    /\ UNCHANGED <<closed, cancelled, retried>> /\ UNCHANGED target

\* clientStream.CloseSend: the empty EOM (sent even after the call ended).
CloseSend(t) ==
    /\ ~closed[t]
    /\ closed' = [closed EXCEPT ![t] = TRUE]
    /\ net' = Append(net, [t |-> t, kind |-> "eom",
                           cont |-> sent[t] > 0 /\ Mutant # "old-caller", retry |-> FALSE])
    /\ UNCHANGED <<sent, cancelled, retried>> /\ UNCHANGED target

\* clientStream.sendCancel: the caller left.
Cancel(t) ==
    /\ sent[t] > 0 \/ Mutant = "cancel-unreached"
    /\ ~cancelled[t]
    /\ cancelled' = [cancelled EXCEPT ![t] = TRUE]
    /\ net' = Append(net, [t |-> t, kind |-> "cancel", cont |-> FALSE, retry |-> FALSE])
    /\ UNCHANGED <<sent, closed, retried>> /\ UNCHANGED target

\* clientStream.rehandshake (an E2EE resume answered unknown, spec
\* A2ASession.tla Unknown): once per call, before its request end, the
\* caller starts the call again with a handshake that names the resume it
\* retries; its request frames follow as continuations.
Retry(t) ==
    /\ t \in Retries
    /\ sent[t] > 0 /\ ~closed[t] /\ ~retried[t]
    /\ retried' = [retried EXCEPT ![t] = TRUE]
    /\ net' = Append(net, [t |-> t, kind |-> "data", cont |-> FALSE, retry |-> TRUE])
    /\ UNCHANGED <<sent, closed, cancelled>> /\ UNCHANGED target

\* The frame may start a call (handleMessage's new-call branch).
Starts(f) ==
    /\ f.kind = "data"
    /\ Mutant # "drop-unknown"
    /\ ~f.cont \/ Mutant = "late-new-call"

\* The target's receive loop (Agent.handleMessage) takes the head frame.
\* A served call's frames go to its handler (pushRequest; a cancel ends its
\* context, its handler then returns): Serve. An unknown transaction's
\* frame starts a call (Start) or is dropped (Drop).
Serve ==
    /\ net # <<>> /\ Head(net).t \in incoming
    /\ net' = Tail(net)
    /\ UNCHANGED caller /\ UNCHANGED target

Start ==
    /\ net # <<>>
    /\ LET f == Head(net) IN
       /\ f.t \notin incoming /\ Starts(f)
       \* a retry of a call that ran is refused (a2aSessions.retry: its
       \* session took the call number; retry-runs-again: it is not)
       /\ ~f.retry \/ calls[f.t] = 0 \/ Mutant = "retry-runs-again"
       /\ calls' = [calls EXCEPT ![f.t] = @ + 1]
       /\ incoming' = incoming \cup {f.t}
       /\ running' = running \cup {f.t}
    /\ net' = Tail(net)
    /\ UNCHANGED caller /\ UNCHANGED <<refused, late>>

Drop ==
    /\ net # <<>>
    /\ LET f == Head(net) IN
       /\ f.t \notin incoming /\ ~Starts(f)
       /\ late' = (late \/ calls[f.t] > 0)
    /\ net' = Tail(net)
    /\ UNCHANGED caller /\ UNCHANGED <<incoming, running, calls, refused>>

\* The target refuses a call at its start and runs no handler (none
\* registered, a plaintext call to an agent that requires E2EE, a bad E2EE
\* init): it answers an error and keeps nothing.
Refuse ==
    /\ net # <<>>
    /\ LET f == Head(net) IN
       /\ f.t \notin incoming /\ Starts(f)
       /\ refused' = refused \cup {f.t}
       /\ incoming' = IF Mutant = "refused-first-kept" THEN incoming \cup {f.t} ELSE incoming
    /\ net' = Tail(net)
    /\ UNCHANGED caller /\ UNCHANGED <<running, calls, late>>

Deliver == Serve \/ Start \/ Drop \/ Refuse

\* handleCall (or a failed E2EE ack): the handler returned (on its own, on
\* a cancel, on a refusal); its entry is deleted with it (Agent.endServed).
Return(t) ==
    /\ t \in running
    /\ running' = running \ {t}
    /\ incoming' = IF Mutant = "tombstone" THEN incoming ELSE incoming \ {t}
    /\ UNCHANGED caller /\ UNCHANGED <<net, calls, refused, late>>

Next ==
    \/ \E t \in Txns : Send(t) \/ CloseSend(t) \/ Cancel(t) \/ Retry(t) \/ Return(t)
    \/ Deliver

Spec == Init /\ [][Next]_vars /\ WF_vars(Deliver)

----------------------------------------------------------------------------
\* Invariants.

\* AtMostOneCall: a transaction runs at most one handler call.
AtMostOneCall == \A t \in Txns : calls[t] <= 1

\* NoEndedEntry: the target keeps an entry only for a call whose handler
\* runs: nothing per call that ended or was refused (the memory bound).
NoEndedEntry == incoming \subseteq running

\* CancelKnown: a cancel reaches its target only for a call the target
\* started or refused, never ahead of its call's first frame (dropped
\* there, a first frame after it would start a handler whose caller left).
CancelKnown ==
    net # <<>> /\ Head(net).kind = "cancel" /\ Head(net).t \notin incoming
        => calls[Head(net).t] > 0 \/ Head(net).t \in refused

\* AllServed: a call whose first data frame was sent gets its handler call
\* or its refusal.
AllServed == \A t \in Txns : (sent[t] > 0) ~> (calls[t] = 1 \/ t \in refused)

\* Witnesses (each must be violated: scripts/spec.sh mutants).
\* A frame of a call whose handler started reaches the target with no entry.
W_LateFrame == ~late
\* A late data frame: the target gets more of a call after its handler returned.
W_LateData == ~(\E t \in Txns : t \notin running /\ calls[t] = 1 /\ net # <<>>
                 /\ Head(net).t = t /\ Head(net).kind = "data")
\* Both calls served at once.
W_BothRun == ~(running = Txns)
=============================================================================
