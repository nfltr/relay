--------------------------- MODULE TraceAgentStop ---------------------------
(* Trace validation of AgentStop.tla (spec/README.md "AgentStop traces"):
   the steps one directServer took (-tags relaytrace, client/agent
   trace_stop_on.go) must be a behaviour of AgentStop: its sessions
   (Register: every one direct), a target's reset (TargetReset: setDirect's
   cut), each ABORT (Abort: the session was aborted or had ended by then),
   each session's end (Done: its peer's end, answer or reset, or its
   detach bound) and cut (Cut: a StopEnd follows the Cut of every session
   registered by then), and each directServer.stop call (StopBegin
   with whether it drains, DrainEnd with whether the drain ended because
   every session was over or at its deadline, StopReset, StopEnd). Which
   call is which (the primary's, the cycle's end's, the table's) is TLC's
   choice (who). Not logged, so TLC adds them: the stop's signal, the
   Listener.Close steps before the table's call (its resets only of
   sessions already aborted or ended: a logged reset is TargetReset), the
   cycle's end, the targets' bytes and clean closes, a peer vanishing, and
   the clock: a tick here is free (the code's scheduler is no urgent
   step), so the timing properties (ResetEndsInGrace, StopInTime,
   NoDrainOnReset) are the tests' (TestDirectStopsWaitOneGrace,
   TestDirectTargetResetResetsTheSession), not the trace's. Drain is 0:
   the calls may overlap (an agent without a drain), and a drain's end is
   the trace's by. Accepted when TLC reaches the trace's end: TraceNotDone
   is then violated (scripts/spec.sh stoptraces). *)
EXTENDS Json, AgentStop, TLC, Sequences

CONSTANTS TraceFile

Log == ndJsonDeserialize(TraceFile)
TraceSessions == {Log[i].s : i \in {j \in 1..Len(Log) : Log[j].ev = "Register"}}

VARIABLES l, who, reg, cuts
tv == <<who, reg, cuts>>
E == Log[l]

Starts(w) == spc[w] = "idle" /\ spc'[w] # "idle"

Step ==
    CASE E.ev = "Register" -> UNCHANGED vars /\ reg' = reg \cup {E.s} /\ UNCHANGED <<who, cuts>>
      [] E.ev = "TargetReset" ->
            /\ \/ AppReset(E.s)
               \/ (done[E.s] \/ tgt[E.s] = "reset") /\ UNCHANGED vars
            /\ UNCHANGED tv
      [] E.ev = "Abort" -> (aborted[E.s] \/ done[E.s]) /\ UNCHANGED vars /\ UNCHANGED tv
      [] E.ev = "Done" ->
            /\ PeerEnd(E.s) \/ PeerAnswer(E.s) \/ PeerReset(E.s) \/ DetachEnd(E.s)
            /\ UNCHANGED tv
      [] E.ev = "Cut" -> Cut(E.s) /\ UNCHANGED vars /\ cuts' = cuts \cup {E.s} /\ UNCHANGED <<who, reg>>
      [] E.ev = "StopBegin" ->
            \E w \in Calls :
                /\ E.k \notin DOMAIN who
                /\ Next /\ Starts(w)
                /\ (spc'[w] = "drain") = E.drain
                /\ who' = who @@ (E.k :> w) /\ UNCHANGED <<reg, cuts>>
      [] E.ev = "DrainEnd" ->
            /\ E.k \in DOMAIN who
            /\ CallDrainEnd(who[E.k])
            /\ E.by = "over" => \A s \in Direct : Over(s)
            /\ UNCHANGED tv
      [] E.ev = "StopReset" -> E.k \in DOMAIN who /\ CallReset(who[E.k]) /\ UNCHANGED tv
      [] E.ev = "StopEnd" ->
            \* it waited for every session's cut channel (reset's Cut line)
            E.k \in DOMAIN who /\ reg \subseteq cuts /\ CallWaitEnd(who[E.k]) /\ UNCHANGED tv
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

FreeTick ==
    /\ now < MaxTime /\ now' = now + 1
    /\ UNCHANGED agentVars /\ UNCHANGED sessVars

Silent ==
    \/ FreeTick
    \/ Signal
    \/ CycleEnd
    \/ \E c \in Closers :
          \/ Close(c) \/ CloserAgent(c) \/ CloserTable(c) \/ CloserWait(c)
          \/ CloserReset(c) /\ \A s \in Direct : done[s] \/ aborted[s]
    \/ \E s \in Sessions : Write(s) \/ CloseWrite(s) \/ Deliver(s) \/ Vanish(s)

TraceInit == Init /\ l = 1 /\ who = <<>> /\ reg = {} /\ cuts = {}
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ ~ENABLED Step /\ Silent /\ UNCHANGED <<l, tv>>

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
