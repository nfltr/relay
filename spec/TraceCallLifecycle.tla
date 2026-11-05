------------------------- MODULE TraceCallLifecycle -------------------------
(* Trace validation of CallLifecycle.tla (spec/README.md "CallLifecycle
   traces"): the target-side steps a real run recorded (-tags relaytrace,
   client/rpcclient trace_callcredit_on.go traceCL) for one transaction
   (Call) at one agent (Agent) must be a behaviour of CallLifecycle with that transaction alone:
   the receive loop taking a request frame (Serve: to the call it serves;
   Start: a new call; Drop; Refuse: refused at its start) and a served
   call's entry going (Return). Each frame line carries the frame's kind
   and continuation mark, which must be the head frame's. The caller's
   steps (Send, CloseSend, Cancel) are not logged: TLC takes them only when
   the next logged step needs them; a transaction no frame of which is
   marked is checked with an old caller (Mutant "old-caller": tests that
   play the caller by hand mark nothing). Accepted when TLC reaches the trace's
   end: TraceNotDone is then violated (scripts/spec.sh traces). *)
EXTENDS Json, CallLifecycle, TLC

CONSTANTS TraceFile, Agent, Call

Log == SelectSeq(ndJsonDeserialize(TraceFile), LAMBDA e : e.a = Agent /\ e.c = Call)
TraceTxns == {Call}
\* A bound on the frames a caller sends: the run's own.
TraceLen == Len(Log) + 1

VARIABLE l
E == Log[l]

\* The head frame is the logged one.
Head1 == net # <<>> /\ Head(net).kind = E.k /\ Head(net).cont = E.cont

Step ==
    CASE E.ev = "Serve" -> Head1 /\ Serve
      [] E.ev = "Start" -> Head1 /\ Start
      [] E.ev = "Drop" -> Head1 /\ Drop
      [] E.ev = "Refuse" -> Head1 /\ Refuse
      [] E.ev = "Return" -> Return(Call)
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

\* The caller's steps the next logged one waits for.
CallerStep == Send(Call) \/ CloseSend(Call) \/ Cancel(Call)

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ ~ENABLED Step /\ E.ev # "Return" /\ CallerStep /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
