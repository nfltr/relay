------------------------- MODULE CallCredit -------------------------
(* client/rpcclient agent-to-agent calls: one direction of the frames of
   several calls between two agents' connections through the relay, with
   per-call credit (spec/README.md "CallCredit.tla" is the design and maps
   each action to Go).

   The sender (a target's handler sending responses, or a caller sending
   requests) takes one credit per frame; its connection is one FIFO to the
   relay (in). The relay keeps a bounded pipe per call (pipe: its
   TxnRegistry handle and session channels) and forwards it onto the
   receiver's connection, one FIFO (out). The receiver's receive loop serves
   every call on that connection: it takes the frame at the head of out and
   puts it into that call's buffer. The app reads its call's buffer; a
   reader in Stuck never reads. Each frame read is acknowledged in a window
   update of at least a quarter window (link.Credit.Consumed), which goes
   back on the receiver's connection (gin), through the relay (RelayGrant)
   and to the sender (gout). Window updates of the response direction travel
   the request direction, which the caller ends with its CloseSend (Eom):
   the relay forwards them after that end too.

   Mutants (scripts/spec.sh mutants): "no-credit" (the code before: no
   credit, the receive loop waits on a full buffer: handoff.Stall),
   "no-return" (reads grant nothing back), "shared-buffer" (one buffer of W
   frames for the connection, not per call), "drop-after-eom" (the relay
   ends a call's request direction at its EOM and drops its later frames,
   window updates included: the relay before lane CALLCREDIT). *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Calls,   \* the calls on the connection
    Stuck,   \* calls whose reader never reads
    W,       \* the receiver's window per call, in frames
    N,       \* frames each call sends
    P,       \* the relay's pipe per call
    Q,       \* a connection FIFO's capacity (gRPC flow control)
    Mutant

ASSUME Stuck \subseteq Calls /\ W >= 1 /\ N >= 1 /\ P >= 1 /\ Q >= 1

\* A window update goes out once a quarter window was read.
T == IF W \div 4 > 1 THEN W \div 4 ELSE 1

VARIABLES cr, sent, in, pipe, out, buf, got, cons, gin, gout, eom, gone, late
vars == <<cr, sent, in, pipe, out, buf, got, cons, gin, gout, eom, gone, late>>

Range(s) == {s[i] : i \in 1..Len(s)}
\* The entries of s for call c, in order (frames: their numbers; grants: n).
Of(s, c) == LET f[k \in 0..Len(s)] ==
                 IF k = 0 THEN <<>>
                 ELSE IF s[k][1] = c THEN Append(f[k-1], s[k][2]) ELSE f[k-1]
            IN f[Len(s)]
Sum(s) == LET f[k \in 0..Len(s)] == IF k = 0 THEN 0 ELSE f[k-1] + s[k] IN f[Len(s)]
Held == LET f[S \in SUBSET Calls] ==
              IF S = {} THEN 0
              ELSE LET c == CHOOSE x \in S : TRUE IN Len(buf[c]) + f[S \ {c}]
        IN f[Calls]

\* The receive loop can put a frame of c into c's buffer without waiting.
Room(c) == IF Mutant = "shared-buffer" THEN Held < W ELSE Len(buf[c]) < W

TypeOK ==
    /\ cr \in [Calls -> 0..W] /\ sent \in [Calls -> 0..N] /\ got \in [Calls -> 0..N]
    /\ cons \in [Calls -> 0..W] /\ eom \in [Calls -> BOOLEAN] /\ gone \in [Calls -> BOOLEAN]
    /\ late \in BOOLEAN

Init ==
    /\ cr = [c \in Calls |-> W]
    /\ sent = [c \in Calls |-> 0]
    /\ in = <<>> /\ out = <<>> /\ gin = <<>> /\ gout = <<>>
    /\ pipe = [c \in Calls |-> <<>>]
    /\ buf = [c \in Calls |-> <<>>]
    /\ got = [c \in Calls |-> 0]
    /\ cons = [c \in Calls |-> 0]
    /\ eom = [c \in Calls |-> FALSE]
    /\ gone = [c \in Calls |-> FALSE]
    /\ late = FALSE

\* clientStream.Send / serverStream.Send: Credit.Acquire, then sendFrame.
Send(c) ==
    /\ ~gone[c] /\ sent[c] < N /\ Len(in) < Q
    /\ Mutant = "no-credit" \/ cr[c] > 0
    /\ cr' = IF Mutant = "no-credit" THEN cr ELSE [cr EXCEPT ![c] = @ - 1]
    /\ sent' = [sent EXCEPT ![c] = @ + 1]
    /\ in' = Append(in, <<c, sent[c] + 1>>)
    /\ UNCHANGED <<pipe, out, buf, got, cons, gin, gout, eom, gone, late>>

\* The relay's receive loop of the sender's stream hands the frame to its
\* call's pipe; it waits while that pipe is full (TxnRegistry Fanout).
RelayIn ==
    /\ in # <<>>
    /\ LET c == Head(in)[1] IN
       /\ Len(pipe[c]) < P
       /\ pipe' = [pipe EXCEPT ![c] = Append(@, Head(in)[2])]
    /\ in' = Tail(in)
    /\ UNCHANGED <<cr, sent, out, buf, got, cons, gin, gout, eom, gone, late>>

\* The call's route sends it on the receiver's stream (sourceStream.Send).
RelayOut(c) ==
    /\ pipe[c] # <<>> /\ Len(out) < Q
    /\ out' = Append(out, <<c, Head(pipe[c])>>)
    /\ pipe' = [pipe EXCEPT ![c] = Tail(@)]
    /\ UNCHANGED <<cr, sent, in, buf, got, cons, gin, gout, eom, gone, late>>

\* rpcclient recvLoop -> pushResponse / pushRequest. A frame of a call that
\* ended is dropped. Without room the loop waits (only the code before:
\* with credit there is always room, NoHOL).
Deliver ==
    /\ out # <<>>
    /\ LET c == Head(out)[1] IN
       IF gone[c] THEN UNCHANGED buf
       ELSE /\ Room(c)
            /\ buf' = [buf EXCEPT ![c] = Append(@, Head(out)[2])]
    /\ out' = Tail(out)
    /\ UNCHANGED <<cr, sent, in, pipe, got, cons, gin, gout, eom, gone, late>>

\* The app's Recv takes a frame; Credit.Consumed grants a quarter window.
Read(c) ==
    /\ c \notin Stuck /\ ~gone[c] /\ buf[c] # <<>>
    /\ buf' = [buf EXCEPT ![c] = Tail(@)]
    /\ got' = [got EXCEPT ![c] = @ + 1]
    /\ IF cons[c] + 1 >= T /\ Mutant \notin {"no-return", "no-credit"}
       THEN /\ gin' = Append(gin, <<c, cons[c] + 1>>)
            /\ cons' = [cons EXCEPT ![c] = 0]
       ELSE /\ cons' = [cons EXCEPT ![c] = IF Mutant \in {"no-return", "no-credit"} THEN 0 ELSE @ + 1]
            /\ UNCHANGED gin
    /\ UNCHANGED <<cr, sent, in, pipe, out, gout, eom, gone, late>>

\* The caller's CloseSend: the request direction's EOM reaches the relay.
Eom(c) ==
    /\ ~eom[c]
    /\ eom' = [eom EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<cr, sent, in, pipe, out, buf, got, cons, gin, gout, gone, late>>

\* The relay forwards a window update to the sender (its own small channel
\* per call: never waits, never drops while the peer keeps to its credit).
RelayGrant ==
    /\ gin # <<>>
    /\ LET g == Head(gin) IN
       IF Mutant = "drop-after-eom" /\ eom[g[1]]
       THEN UNCHANGED <<gout, late>>
       ELSE /\ gout' = Append(gout, g)
            /\ late' = (late \/ eom[g[1]])
    /\ gin' = Tail(gin)
    /\ UNCHANGED <<cr, sent, in, pipe, out, buf, got, cons, eom, gone>>

\* The sender's receive loop: Credit.Grant.
SenderGrant ==
    /\ gout # <<>>
    /\ LET g == Head(gout) IN
       cr' = IF gone[g[1]] THEN cr ELSE [cr EXCEPT ![g[1]] = @ + g[2]]
    /\ gout' = Tail(gout)
    /\ UNCHANGED <<sent, in, pipe, out, buf, got, cons, gin, eom, gone, late>>

\* A stuck call ends (its caller's context, a cancel, the deadline): both
\* sides forget its credit; what it buffered goes, later frames are dropped.
Cancel(c) ==
    /\ c \in Stuck /\ ~gone[c]
    /\ gone' = [gone EXCEPT ![c] = TRUE]
    /\ buf' = [buf EXCEPT ![c] = <<>>]
    /\ UNCHANGED <<cr, sent, in, pipe, out, got, cons, gin, gout, eom, late>>

Next ==
    \/ \E c \in Calls : Send(c) \/ RelayOut(c) \/ Read(c) \/ Eom(c) \/ Cancel(c)
    \/ RelayIn \/ Deliver \/ RelayGrant \/ SenderGrant

Fairness ==
    /\ \A c \in Calls : WF_vars(Send(c)) /\ WF_vars(RelayOut(c)) /\ WF_vars(Eom(c))
    /\ \A c \in Calls \ Stuck : WF_vars(Read(c))
    /\ WF_vars(RelayIn) /\ WF_vars(Deliver) /\ WF_vars(RelayGrant) /\ WF_vars(SenderGrant)

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
\* Invariants.

\* NoHOL: the frame at the head of the receiver's connection always fits
\* its call's buffer: the receive loop never waits on one call.
NoHOL == out # <<>> => (gone[Head(out)[1]] \/ Room(Head(out)[1]))

\* BufferBound: a call's buffer holds at most its window; a relay pipe its cap.
BufferBound == \A c \in Calls : Len(buf[c]) <= W /\ Len(pipe[c]) <= P

\* Conservation: a live call's credit, its frames on the way, buffered,
\* read and not yet acknowledged, and its window updates on the way make
\* up the receiver's window.
InFlight(c) == Len(Of(in, c)) + Len(pipe[c]) + Len(Of(out, c))
Conservation == \A c \in Calls : ~gone[c] =>
    cr[c] + InFlight(c) + Len(buf[c]) + cons[c] + Sum(Of(gin, c)) + Sum(Of(gout, c)) = W

\* GrantBound: a call has at most W \div T window updates on the way, so the
\* relay's channel of them (a2aWindowCap) is never full.
GrantBound == \A c \in Calls : Len(Of(gin, c)) + Len(Of(gout, c)) <= W \div T

\* Ordered: each call's frames along its path are the next ones, once each.
Seq1(a, b) == [k \in 1..(b - a + 1) |-> a + k - 1]
Ordered == \A c \in Calls : ~gone[c] =>
    buf[c] \o Of(out, c) \o pipe[c] \o Of(in, c) = Seq1(got[c] + 1, sent[c])

\* Liveness: every call whose reader reads gets all its frames, whatever a
\* stuck call does.
HealthyDone == \A c \in Calls \ Stuck : <>(got[c] = N)

\* Witnesses (each must be violated: scripts/spec.sh mutants).
W_StuckFullHealthyDone == ~(\E s \in Stuck, h \in Calls \ Stuck :
    ~gone[s] /\ Len(buf[s]) = W /\ got[h] = N)
W_RelayPipeFull == ~(in # <<>> /\ Len(pipe[Head(in)[1]]) = P)
W_LateGrant == ~late
W_SenderWaits == ~(\E c \in Calls : ~gone[c] /\ sent[c] < N /\ cr[c] = 0)
W_CancelDrop == ~(out # <<>> /\ gone[Head(out)[1]])
=============================================================================
