----------------------------- MODULE AgentStop -----------------------------
(* An agent's stop (spec/README.md "AgentStop.tla"): its sessions, relayed
   and direct, end within the drain and one grace, a reset session is
   never drained, and the process exits only once every session ended or
   its peer was told.

   Sessions: each relayed (rides the agent's link through the relay) or
   direct (a pathswitch session on the agent's own QUIC path; Direct). A
   session's target (the local end: a QueueConn, an nfnet Conn) writes
   bytes, closes cleanly (CloseWrite: its tail committed) or resets. Its
   peer delivers the bytes, ends at the clean close (PeerEnd), answers an
   ABORT (PeerAnswer), resets on its own (PeerReset) or vanishes (killed:
   Vanish), and then answers nothing. A relayed session's vanished peer
   is cut by the relay (RelayCut); a direct one's only by the agent's
   grace or the session's own detach bound (DetachEnd).

   The stop: a signal (Signal: nfltr up's SIGTERM, the agent's ctx), or
   nfnet's Listener.Close (Close): it resets the accepted Conns
   (CloserReset), stops the agent (CloserAgent), waits for it
   (CloserAwait), closes the service table (its own directServer.stop,
   the "table" call), and returns; a second Close waits for the first
   (CloserWait, lane SENDBEST). The agent's stop (connect.go): its relayed
   sessions run until they end or Drain passes (waitIdle), then the
   primary's directServer.stop runs (PrimaryStart, call "primary"); the
   cycle's end runs its own (CycleStart, call "cycle") after the primary
   returned, or with no drain at once (both calls together), then resets
   the relayed sessions left (CycleEnd: endTCP, the link's end). Each
   directServer.stop call: the first drains the direct sessions until each
   ended or was reset, or Drain passed (CallDrainEnd; stopped), then every
   call resets the direct sessions left (CallReset: an ABORT, at most once
   per session) and waits for each until it ended or Grace passed since
   its first reset (CallWaitEnd: directSession.reset's cut). The process
   exits once a Close returned or, with none called, the agent stopped
   (Exit).

   Time: a Tick is one unit; the agent's own steps are urgent (Tick waits
   for them: Urgent), the targets', peers' and relay's are not (a peer may
   be slow, which is a vanished peer until it answers). The clock starts
   at the stop: what happened before it is an order of steps, all at
   time 0 (the bounds are from the stop). Mutant puts back
   one bug each (scripts/spec.sh mutants). *)
EXTENDS Integers, FiniteSets

CONSTANTS Sessions, Direct, Closers, Drain, Grace, MaxBytes, MaxTime, Mutant

ASSUME Direct \subseteq Sessions /\ Drain \in Nat /\ Grace \in Nat
ASSUME Mutant \in {"none", "no-target-cut", "drain-waits-reset", "grace-per-stop",
                   "second-close-returns", "no-drain", "reset-as-close", "no-grace"}

Relayed == Sessions \ Direct
Calls == {"primary", "cycle", "table"}
None == -1
Times == None..MaxTime

VARIABLES
    now,      \* the clock
    stopAt,   \* when the agent's stop began; None: running
    apc,      \* the agent: run, stopping, stopped (its cycle ended)
    spc,      \* each directServer.stop call: idle, drain, reset, wait, done
    wfrom,    \* when each call began its wait (grace-per-stop only)
    stopped,  \* directServer.stopped: a call's drain ended
    cl,       \* each Listener.Close: idle, reset, agent, await, table, wait, done
    closed,   \* Listener.closed
    exited,   \* the process exited
    tgt,      \* each session's target: open, closed (clean, tail committed), reset
    wrote,    \* bytes the target wrote (committed)
    dlv,      \* bytes the peer received
    peer,     \* alive, gone (killed)
    pview,    \* how the peer saw the session end: open, eof, reset
    aborted,  \* directSession.aborted (direct) or the relay's reset (relayed)
    abortAt,  \* when it was first aborted; None: never
    resetAt,  \* when its target reset it; None: never
    done      \* the session ended (pathswitch Done; relayed: its stream ended)

vars == <<now, stopAt, apc, spc, wfrom, stopped, cl, closed, exited,
          tgt, wrote, dlv, peer, pview, aborted, abortAt, resetAt, done>>
agentVars == <<stopAt, apc, spc, wfrom, stopped, cl, closed, exited>>
sessVars == <<tgt, wrote, dlv, peer, pview, aborted, abortAt, resetAt, done>>

TypeOK ==
    /\ now \in 0..MaxTime /\ stopAt \in Times
    /\ apc \in {"run", "stopping", "stopped"}
    /\ spc \in [Calls -> {"idle", "drain", "reset", "wait", "done"}]
    /\ wfrom \in [Calls -> Times] /\ stopped \in BOOLEAN
    /\ cl \in [Closers -> {"idle", "reset", "agent", "await", "table", "wait", "done"}]
    /\ closed \in BOOLEAN /\ exited \in BOOLEAN
    /\ tgt \in [Sessions -> {"open", "closed", "reset"}]
    /\ wrote \in [Sessions -> 0..MaxBytes] /\ dlv \in [Sessions -> 0..MaxBytes]
    /\ peer \in [Sessions -> {"alive", "gone"}]
    /\ pview \in [Sessions -> {"open", "eof", "reset"}]
    /\ aborted \in [Sessions -> BOOLEAN] /\ abortAt \in [Sessions -> Times]
    /\ resetAt \in [Sessions -> Times] /\ done \in [Sessions -> BOOLEAN]

Init ==
    /\ now = 0 /\ stopAt = None /\ apc = "run"
    /\ spc = [k \in Calls |-> "idle"] /\ wfrom = [k \in Calls |-> None]
    /\ stopped = FALSE /\ cl = [c \in Closers |-> "idle"]
    /\ closed = FALSE /\ exited = FALSE
    /\ tgt = [s \in Sessions |-> "open"] /\ wrote = [s \in Sessions |-> 0]
    /\ dlv = [s \in Sessions |-> 0] /\ peer = [s \in Sessions |-> "alive"]
    /\ pview = [s \in Sessions |-> "open"] /\ aborted = [s \in Sessions |-> FALSE]
    /\ abortAt = [s \in Sessions |-> None] /\ resetAt = [s \in Sessions |-> None]
    /\ done = [s \in Sessions |-> FALSE]

\* A session ended, or Grace passed since its first reset: nothing waits
\* for it any more (directSession.cut).
Cut(s) == done[s] \/ (aborted[s] /\ now >= abortAt[s] + Grace)
Deadline == stopAt + Drain
\* The drain waits no more for s: it ended, or was reset already
\* (SENDCUT: a target's reset is not drained).
Over(s) == done[s] \/ (aborted[s] /\ Mutant # "drain-waits-reset")

\* abort(S): the sessions of S not yet ended or aborted get their ABORT now.
Abort(S) ==
    /\ aborted' = [s \in Sessions |-> aborted[s] \/ (s \in S /\ ~done[s])]
    /\ abortAt' = [s \in Sessions |->
                     IF s \in S /\ ~done[s] /\ ~aborted[s] THEN now ELSE abortAt[s]]

\* The target resets the sessions of S: a relayed one ends at once (the
\* relay resets its peer); a direct one is aborted at once (setDirect's
\* cut; no-target-cut: only once Join's copy toward the peer reads it,
\* Propagate).
TargetReset(S) ==
    /\ tgt' = [s \in Sessions |-> IF s \in S THEN "reset" ELSE tgt[s]]
    /\ resetAt' = [s \in Sessions |-> IF s \in S THEN now ELSE resetAt[s]]
    /\ done' = [s \in Sessions |-> done[s] \/ (s \in S /\ s \in Relayed)]
    /\ pview' = [s \in Sessions |->
                   IF s \in S /\ s \in Relayed /\ peer[s] = "alive" THEN "reset" ELSE pview[s]]
    /\ Abort(IF Mutant = "no-target-cut" THEN S \cap Relayed ELSE S)

\* A call k starts: it drains unless a call's drain ended (stopped).
StartCall(k) ==
    /\ spc' = [spc EXCEPT ![k] = IF stopped THEN "reset" ELSE "drain"]

\* ---- the agent's stop (connect.go) ----

BeginStop == apc' = "stopping" /\ stopAt' = now

Signal ==
    /\ apc = "run" /\ ~exited
    /\ BeginStop
    /\ UNCHANGED <<now, spc, wfrom, stopped, cl, closed, exited>> /\ UNCHANGED sessVars

\* The primary's: once its relayed sessions ended or Drain passed
\* (waitIdle), its directServer.stop.
PrimaryStart ==
    /\ apc # "run" /\ spc["primary"] = "idle"
    /\ \A r \in Relayed : done[r] \/ now >= Deadline
    /\ StartCall("primary")
    /\ UNCHANGED <<now, stopAt, apc, wfrom, stopped, cl, closed, exited>> /\ UNCHANGED sessVars

\* The cycle's end's directServer.stop: after the primary returned, or,
\* without a drain, at once (the cycle returns at the stop, its primary
\* still running: both calls may run together).
CycleStart ==
    /\ apc = "stopping" /\ spc["cycle"] = "idle"
    /\ spc["primary"] = "done" \/ Drain = 0
    /\ StartCall("cycle")
    /\ UNCHANGED <<now, stopAt, apc, wfrom, stopped, cl, closed, exited>> /\ UNCHANGED sessVars

CycleEnd ==
    /\ apc = "stopping" /\ spc["cycle"] = "done"
    /\ apc' = "stopped"
    /\ done' = [s \in Sessions |-> done[s] \/ s \in Relayed]
    /\ pview' = [s \in Sessions |->
                   IF s \in Relayed /\ ~done[s] /\ peer[s] = "alive" THEN "reset" ELSE pview[s]]
    /\ Abort(Relayed)
    /\ UNCHANGED <<now, stopAt, spc, wfrom, stopped, cl, closed, exited>>
    /\ UNCHANGED <<tgt, wrote, dlv, peer, resetAt>>

\* ---- directServer.stop, call k ----

CallDrainEnd(k) ==
    /\ spc[k] = "drain"
    /\ Mutant = "no-drain" \/ now >= Deadline \/ \A s \in Direct : Over(s)
    /\ spc' = [spc EXCEPT ![k] = "reset"] /\ stopped' = TRUE
    /\ UNCHANGED <<now, stopAt, apc, wfrom, cl, closed, exited>> /\ UNCHANGED sessVars

CallReset(k) ==
    /\ spc[k] = "reset"
    /\ Abort(Direct)
    /\ spc' = [spc EXCEPT ![k] = "wait"] /\ wfrom' = [wfrom EXCEPT ![k] = now]
    /\ UNCHANGED <<now, stopAt, apc, stopped, cl, closed, exited>>
    /\ UNCHANGED <<tgt, wrote, dlv, peer, pview, resetAt, done>>

CallWaitEnd(k) ==
    /\ spc[k] = "wait"
    /\ CASE Mutant = "grace-per-stop" ->
              \A s \in Direct : done[s] \/ now >= wfrom[k] + Grace
         [] Mutant = "no-grace" -> TRUE
         [] OTHER -> \A s \in Direct : Cut(s)
    /\ spc' = [spc EXCEPT ![k] = "done"]
    /\ UNCHANGED <<now, stopAt, apc, wfrom, stopped, cl, closed, exited>> /\ UNCHANGED sessVars

\* ---- nfnet's Listener.Close ----

Close(c) ==
    /\ cl[c] = "idle" /\ ~exited
    /\ IF closed
       THEN /\ cl' = [cl EXCEPT ![c] = IF Mutant = "second-close-returns" THEN "done" ELSE "wait"]
            /\ UNCHANGED closed
       ELSE /\ cl' = [cl EXCEPT ![c] = "reset"] /\ closed' = TRUE
    /\ UNCHANGED <<now, stopAt, apc, spc, wfrom, stopped, exited>> /\ UNCHANGED sessVars

\* Its accepted Conns (the sessions not ended) are reset.
CloserReset(c) ==
    /\ cl[c] = "reset"
    /\ TargetReset({s \in Sessions : ~done[s] /\ tgt[s] # "reset"})
    /\ cl' = [cl EXCEPT ![c] = "agent"]
    /\ UNCHANGED <<now, stopAt, apc, spc, wfrom, stopped, closed, exited>>
    /\ UNCHANGED <<wrote, dlv, peer>>

CloserAgent(c) ==
    /\ cl[c] = "agent"
    /\ IF apc = "run" THEN BeginStop ELSE UNCHANGED <<apc, stopAt>>
    /\ cl' = [cl EXCEPT ![c] = "await"]
    /\ UNCHANGED <<now, spc, wfrom, stopped, closed, exited>> /\ UNCHANGED sessVars

CloserAwait(c) ==
    /\ cl[c] = "await" /\ apc = "stopped"
    /\ cl' = [cl EXCEPT ![c] = "table"] /\ StartCall("table")
    /\ UNCHANGED <<now, stopAt, apc, wfrom, stopped, closed, exited>> /\ UNCHANGED sessVars

CloserTable(c) ==
    /\ cl[c] = "table" /\ spc["table"] = "done"
    /\ cl' = [cl EXCEPT ![c] = "done"]
    /\ UNCHANGED <<now, stopAt, apc, spc, wfrom, stopped, closed, exited>> /\ UNCHANGED sessVars

\* A second Close returns once the first one did (l.shut).
CloserWait(c) ==
    /\ cl[c] = "wait"
    /\ \E d \in Closers : d # c /\ cl[d] = "done"
    /\ cl' = [cl EXCEPT ![c] = "done"]
    /\ UNCHANGED <<now, stopAt, apc, spc, wfrom, stopped, closed, exited>> /\ UNCHANGED sessVars

Exit ==
    /\ ~exited
    /\ \/ apc = "stopped" /\ \A c \in Closers : cl[c] = "idle"
       \/ \E c \in Closers : cl[c] = "done"
    /\ exited' = TRUE
    /\ UNCHANGED <<now, stopAt, apc, spc, wfrom, stopped, cl, closed>> /\ UNCHANGED sessVars

\* ---- the targets ----

Live(s) == ~done[s] /\ ~aborted[s] /\ ~exited

Write(s) ==
    /\ Live(s) /\ tgt[s] = "open" /\ wrote[s] < MaxBytes
    /\ wrote' = [wrote EXCEPT ![s] = @ + 1]
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<tgt, dlv, peer, pview, aborted, abortAt, resetAt, done>>

CloseWrite(s) ==
    /\ Live(s) /\ tgt[s] = "open"
    /\ tgt' = [tgt EXCEPT ![s] = "closed"]
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<wrote, dlv, peer, pview, aborted, abortAt, resetAt, done>>

AppReset(s) ==
    /\ ~done[s] /\ ~exited /\ tgt[s] # "reset"
    /\ TargetReset({s})
    /\ UNCHANGED agentVars /\ UNCHANGED <<now, wrote, dlv, peer>>

\* no-target-cut: Join's copy toward the peer reads the target's reset
\* only while the peer takes bytes.
Propagate(s) ==
    /\ s \in Direct /\ tgt[s] = "reset" /\ ~aborted[s] /\ ~done[s] /\ peer[s] = "alive"
    /\ ~exited
    /\ Abort({s})
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<tgt, wrote, dlv, peer, pview, resetAt, done>>

\* ---- the peers and the relay ----

Deliver(s) ==
    /\ peer[s] = "alive" /\ dlv[s] < wrote[s] /\ ~aborted[s] /\ ~done[s] /\ ~exited
    /\ dlv' = [dlv EXCEPT ![s] = @ + 1]
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<tgt, wrote, peer, pview, aborted, abortAt, resetAt, done>>

PeerEnd(s) ==
    /\ peer[s] = "alive" /\ tgt[s] = "closed" /\ dlv[s] = wrote[s]
    /\ ~aborted[s] /\ ~done[s] /\ ~exited
    /\ pview' = [pview EXCEPT ![s] = "eof"] /\ done' = [done EXCEPT ![s] = TRUE]
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<tgt, wrote, dlv, peer, aborted, abortAt, resetAt>>

\* The peer received the ABORT and answers it (reset-as-close: the
\* stop's reset reached it as a clean end).
PeerAnswer(s) ==
    /\ s \in Direct /\ peer[s] = "alive" /\ aborted[s] /\ ~done[s] /\ ~exited
    /\ pview' = [pview EXCEPT ![s] = IF Mutant = "reset-as-close" THEN "eof" ELSE "reset"]
    /\ done' = [done EXCEPT ![s] = TRUE]
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<tgt, wrote, dlv, peer, aborted, abortAt, resetAt>>

PeerReset(s) ==
    /\ peer[s] = "alive" /\ ~done[s] /\ ~exited
    /\ done' = [done EXCEPT ![s] = TRUE]
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<tgt, wrote, dlv, peer, pview, aborted, abortAt, resetAt>>

Vanish(s) ==
    /\ peer[s] = "alive" /\ ~done[s] /\ ~exited
    /\ peer' = [peer EXCEPT ![s] = "gone"]
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<tgt, wrote, dlv, pview, aborted, abortAt, resetAt, done>>

RelayCut(s) ==
    /\ s \in Relayed /\ peer[s] = "gone" /\ ~done[s] /\ ~exited
    /\ done' = [done EXCEPT ![s] = TRUE]
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<tgt, wrote, dlv, peer, pview, aborted, abortAt, resetAt>>

\* A direct session whose peer is gone ends at its detach bound.
DetachEnd(s) ==
    /\ s \in Direct /\ peer[s] = "gone" /\ aborted[s] /\ ~done[s] /\ ~exited
    /\ done' = [done EXCEPT ![s] = TRUE]
    /\ UNCHANGED agentVars /\ UNCHANGED now
    /\ UNCHANGED <<tgt, wrote, dlv, peer, pview, aborted, abortAt, resetAt>>

\* ---- time ----

Urgent ==
    \/ PrimaryStart \/ CycleStart \/ CycleEnd \/ Exit
    \/ \E k \in Calls : CallDrainEnd(k) \/ CallReset(k) \/ CallWaitEnd(k)
    \/ \E c \in Closers : CloserReset(c) \/ CloserAgent(c) \/ CloserAwait(c)
                         \/ CloserTable(c) \/ CloserWait(c)

Tick ==
    /\ now < MaxTime /\ ~exited /\ apc # "run" /\ ~ENABLED Urgent
    /\ now' = now + 1
    /\ UNCHANGED agentVars /\ UNCHANGED sessVars

Env ==
    \/ Signal
    \/ \E c \in Closers : Close(c)
    \/ \E s \in Sessions : Write(s) \/ CloseWrite(s) \/ AppReset(s) \/ Propagate(s)
                          \/ Deliver(s) \/ PeerEnd(s) \/ PeerAnswer(s) \/ PeerReset(s)
                          \/ Vanish(s) \/ RelayCut(s) \/ DetachEnd(s)

Next == Urgent \/ Env \/ Tick

Spec == Init /\ [][Next]_vars

\* ---- properties ----

\* No committed byte lost: a peer sees a clean end only after every byte
\* the target wrote, and only at the target's clean close; any other end
\* is a reset the peer sees as one.
NoSilentLoss == \A s \in Sessions : pview[s] = "eof" => dlv[s] = wrote[s] /\ tgt[s] = "closed"

\* The stop resets a session its target did not reset only once the drain
\* passed: a committed tail gets the drain to arrive.
NoEarlyReset ==
    \A s \in Sessions : aborted[s] /\ tgt[s] # "reset" =>
        stopAt # None /\ abortAt[s] >= Deadline

\* A session its target reset is cut once one grace passed since that
\* reset (SENDCUT: it waited for the drain first).
ResetEndsInGrace ==
    \A s \in Direct : resetAt[s] # None /\ ~Cut(s) => now < resetAt[s] + Grace

\* The stop ends within the drain and one grace: every session ended or
\* was cut by then (ExitAfterEnd), whatever peers vanished.
StopInTime == stopAt # None /\ ~exited => now <= Deadline + Grace

\* The process exits only once every session ended or Grace passed since
\* its ABORT (its peer heard of the end; SENDBEST: not while another Close
\* is still resetting).
ExitAfterEnd == exited => \A s \in Sessions : Cut(s)

\* A reset session is never drained: time does not pass in the drain once
\* every direct session ended or its target reset it.
DrainOnlyReset == (\E k \in Calls : spc[k] = "drain") /\ \A s \in Direct : done[s] \/ tgt[s] = "reset"
NoDrainOnReset == [][Tick => ~DrainOnlyReset]_vars

\* ---- witnesses (each must be violated: scripts/spec.sh mutants) ----

\* The process exits after a direct peer was killed: its grace cut it.
W_GoneCut == ~(exited /\ \E s \in Direct : peer[s] = "gone" /\ ~done[s])
\* The stop takes the whole bound.
W_FullBound == ~(exited /\ stopAt # None /\ now = Deadline + Grace)
\* The stop resets a session its target did not.
W_StopReset == ~(\E s \in Sessions : aborted[s] /\ tgt[s] # "reset")
\* A peer gets every byte and the clean end after the stop began.
W_Eof == ~(\E s \in Sessions : pview[s] = "eof" /\ wrote[s] = MaxBytes /\ stopAt # None)
\* A reset direct session whose peer is gone is cut by its grace.
W_ResetCut == ~(\E s \in Direct : resetAt[s] # None /\ peer[s] = "gone" /\ Cut(s) /\ ~done[s])
\* A target's reset session while the drain runs.
W_DrainWaits == ~((\E k \in Calls : spc[k] = "drain") /\ \E s \in Direct : tgt[s] = "reset" /\ ~done[s])
\* Both Closes return before the process exits.
W_SecondClose == ~(\A c \in Closers : cl[c] = "done")
=============================================================================
