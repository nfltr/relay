------------------------- MODULE TraceCallCredit -------------------------
(* Trace validation of CallCredit.tla (spec/README.md "CallCredit traces"):
   the steps a real run recorded (-tags relaytrace, client/rpcclient
   trace_callcredit_on.go) for one call (Call) in one direction (Dir: "req"
   its requests, "resp" its responses) must be a behaviour of CallCredit
   with that call alone: the sender's Send, the receiver's receive loop
   putting a frame into the call's buffer (Deliver), the app's Read (and
   the window update CallCredit says it sends), the caller's request EOM
   (Eom, of the response direction), the sender taking a window update
   (Grant, its count n) and the caller leaving (Cancel: End). The relay's
   steps (RelayIn, RelayOut, RelayGrant) are not logged: TLC takes them
   only when the next logged step needs them, so a trace is checked against
   the shortest relay schedule that admits it. One call at a time: frames
   and window updates of different calls on one connection are ordered by
   goroutines the recorder does not see, and calls share nothing else.
   Accepted when TLC reaches the trace's end: TraceNotDone is then violated
   (scripts/spec.sh traces). *)
EXTENDS Json, CallCredit, TLC

CONSTANTS TraceFile, Dir, Call

Log == SelectSeq(ndJsonDeserialize(TraceFile), LAMBDA e : e.d = Dir /\ e.c = Call)
TraceCalls == {Call}
\* A bound on frames, pipe and connection capacity: the run's own.
TraceLen == Len(Log) + 1

VARIABLE l
E == Log[l]

Step ==
    CASE E.ev = "Send" -> Send(Call)
      [] E.ev = "Deliver" -> out # <<>> /\ Head(out)[1] = Call /\ Deliver
      [] E.ev = "Read" -> Read(Call)
      [] E.ev = "Eom" -> Eom(Call)
      [] E.ev = "Grant" -> gout # <<>> /\ Head(gout) = <<Call, E.n>> /\ SenderGrant
      [] E.ev = "Cancel" -> End(Call)
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

\* The relay's steps the next logged one waits for.
Relay ==
    CASE E.ev = "Deliver" -> RelayIn \/ RelayOut(Call)
      [] E.ev = "Grant" -> RelayGrant
      [] OTHER -> FALSE

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ ~ENABLED Step /\ Relay /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
