----------------------------- MODULE TraceTLSEnd -----------------------------
(* Trace validation of TLSEnd.tla (spec/README.md "TLSEnd traces", lane    *)
(* ENDTRACE): the steps one direction of a session's end under end-to-end *)
(* TLS took (-tags relaytrace, client/tlsend trace_on.go) must be a        *)
(* behaviour of TLSEnd, in order. Logged: X's close_notify (Notify,        *)
(* XNotify), its transport's end (Fin, XFin), the end of its               *)
(* CloseWriteSync's wait (End: n 1 nil, XRecv to clean; 0 an error, XRecv  *)
(* to reset), Y's read of the close_notify (EOF, YRecv of it), Y's Close   *)
(* (Close, YClose: n 1 it takes the transport's end first, the only Close *)
(* of a Y on a transport that acknowledges ends; n 0 is close-at-notify's) *)
(* and its whole close (Closed, YClosed). Not logged, so TLC adds them:  *)
(* Y's Mux reading the close_notify and the FIN (YRecv), X's reading a frame *)
(* while X waits for nothing. keep is TLC's choice (a Fin logged: FALSE). Accepted when TLC  *)
(* reaches the trace's end with Y's Close returned (YCloses on the         *)
(* finished run): TraceUnfinished violated.                                *)
EXTENDS TLSEnd, Json, TLC, Sequences

CONSTANTS TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLE l
traceVars == <<vars, l>>

E == Log[l]

\* Y's Mux takes the close_notify's bytes and the FIN behind it (YRecv)
\* before Y's app reads the close_notify (EOF): the ENDACK X's wait ends
\* at (End) can come before that read.
Env ==
    \/ x2y # <<>> /\ YRecv
    \/ xs # "wait" /\ XRecv

Step ==
    CASE E.ev = "Notify" -> XNotify
      [] E.ev = "Fin" -> XFin
      [] E.ev = "End" -> XRecv /\ xs = "wait" /\ xs' = IF E.n = 1 THEN "clean" ELSE "reset"
      [] E.ev = "EOF" -> yeof /\ UNCHANGED vars  \* Y's app reads the close_notify its Mux took (Env)
      [] E.ev = "Close" -> YClose /\ E.n = 1   \* n 0: Close at the close_notify (close-at-notify's YClose)
      [] E.ev = "Closed" -> YClosed
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

TraceInit == Init /\ l = 1
TraceNext == (l <= Len(Log) /\ Step /\ l' = l + 1) \/ (Env /\ UNCHANGED l)

\* Violated once every line was taken and Y's Close returned.
TraceUnfinished == l <= Len(Log) \/ ys = "closing"
=============================================================================
