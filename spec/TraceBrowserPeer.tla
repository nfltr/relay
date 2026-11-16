------------------------- MODULE TraceBrowserPeer -------------------------
(* Trace validation of BrowserPeer.tla (spec/README.md "BrowserPeer
   traces"): the steps the agent took for one control session in a real
   run (-tags relaytrace, client/p2p browserpeer_trace_on.go) must be a
   behaviour of BrowserPeer: the control session's open, admission and end
   (CtlOpen, CtlAdmit, CtlEnd), the connection made for its offer (Offer),
   up or failed (PCUp, PCFail; a connection the visitor closed is a
   failure to the agent), reaped (Reap), and each data channel stream's
   steps (OpenDC, Deliver, Complete, Break, Refuse). The visitor's
   WebSocket streams are not the agent's to see (OpenWS is never needed).
   The streams are the trace's, the data channel cap the run's (its Serve
   line), the connection failures bounded by the trace's length. Accepted
   when TLC reaches the trace's end: TraceNotDone is then violated
   (scripts/spec.sh bptraces). *)
EXTENDS Json, BrowserPeer, Sequences, TLC

CONSTANTS TraceFile

Log == ndJsonDeserialize(TraceFile)
TraceLen == Len(Log) + 1
TraceN == LET ss == {Log[i].s : i \in {j \in 1..Len(Log) : "s" \in DOMAIN Log[j]}}
          IN IF ss = {} THEN 1 ELSE CHOOSE m \in ss : \A x \in ss : x <= m
TraceMaxDC == Log[1].maxdc

VARIABLE l
E == Log[l]

Step ==
    CASE E.ev = "Serve" -> UNCHANGED vars
      [] E.ev = "CtlOpen" -> CtlOpen
      [] E.ev = "CtlAdmit" -> CtlAdmit
      [] E.ev = "CtlEnd" -> CtlEnd
      [] E.ev = "Offer" -> Offer
      [] E.ev = "PCUp" -> PCUp
      [] E.ev = "PCFail" -> PCFail
      [] E.ev = "Reap" -> Reap
      [] E.ev = "OpenDC" -> OpenDC(E.s)
      [] E.ev = "Deliver" -> Deliver(E.s)
      [] E.ev = "Complete" -> Complete(E.s)
      [] E.ev = "Break" -> Break(E.s)
      [] E.ev = "Refuse" -> Refuse(E.s)
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

TraceInit == Init /\ l = 1
TraceNext == l <= Len(Log) /\ Step /\ l' = l + 1

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
