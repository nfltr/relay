----------------------- MODULE TraceCallCreditBoth -----------------------
(* Trace validation of CallCreditBoth.tla (spec/README.md "CallCredit
   traces"): the steps a real run recorded (-tags relaytrace, client/rpcclient
   trace_callcredit_on.go) for one call (Call), both directions at once, must
   be a behaviour of CallCreditBoth with that call alone: a Send of either
   direction, a receive loop putting a data frame into the call's buffer
   (Deliver, the receiver's loop) or a window update into its credit (Grant,
   the sender's loop, its count n), the app's Read (and the window update
   CallCreditBoth says it sends on the reader's connection), the caller's
   request EOM (Eom: CloseSend, after the call's requests: NReq is the
   trace's own count) and the caller leaving (Cancel: the call is one of
   Ends, so its direction with no Read is stuck: scripts/spec.sh sets
   StuckReq, StuckResp). Start (a serverStream.Send about to take credit) is
   CallCreditSenders.tla's step and no step here. The relay's steps (RelayIn,
   RelayOut, RelayGrant) and a receive loop dropping a frame of an ended call
   are not logged: TLC takes them only when the next logged step needs them.
   One call at a time, as TraceCallCredit.tla. Accepted when TLC reaches the
   trace's end: TraceNotDone is then violated (scripts/spec.sh). *)
EXTENDS Json, CallCreditBoth, TLC

CONSTANTS TraceFile, Call

Log == SelectSeq(ndJsonDeserialize(TraceFile), LAMBDA e : e.c = Call /\ e.ev # "Start")
TraceCalls == {Call}
TraceLen == Len(Log) + 1
\* The call's requests: CloseSend comes after them.
TraceNReq == Len(SelectSeq(Log, LAMBDA e : e.ev = "Send" /\ e.d = "req"))

VARIABLE l
E == Log[l]

HeadIs(a, k, d) == down[a] # <<>> /\ Head(down[a]).k = k /\ Head(down[a]).d = d /\ Head(down[a]).c = Call

Step ==
    CASE E.ev = "Send" -> Send(E.d, Call)
      [] E.ev = "Deliver" -> HeadIs(Receiver(E.d), "data", E.d) /\ Deliver(Receiver(E.d))
      [] E.ev = "Read" -> Read(E.d, Call)
      [] E.ev = "Eom" -> CloseSend(Call)
      [] E.ev = "Grant" -> HeadIs(Sender(E.d), "grant", E.d) /\ Head(down[Sender(E.d)]).n = E.n /\ Deliver(Sender(E.d))
      [] E.ev = "Cancel" -> Cancel(Call)
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

\* The steps no recorder logs: the relay's, and a receive loop dropping a
\* frame of the ended call.
Hidden ==
    \/ \E a \in Agents : RelayIn(a) \/ (down[a] # <<>> /\ gone[Head(down[a]).c] /\ Deliver(a))
    \/ \E d \in Dirs : RelayOut(d, Call) \/ RelayGrant(d, Call)

TraceInit == Init /\ l = 1
TraceNext ==
    /\ l <= Len(Log)
    /\ \/ Step /\ l' = l + 1
       \/ ~ENABLED Step /\ Hidden /\ UNCHANGED l

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
