-------------------------- MODULE TraceSignalConn --------------------------
(* Trace validation of SignalConn.tla (spec/README.md "Trace validation"):  *)
(* the steps a real run recorded (-tags relaytrace, client/p2p trace_on.go) *)
(* for one direction, writer W to reader R, must be a behaviour of the     *)
(* fixed SignalConn: W's writes, W's direct path joining, R's reads, and   *)
(* either side's reader of a path ending (the first is the path's Break).  *)
(* Accepted when TLC reaches the trace's end: TraceNotDone is then violated *)
(* (scripts/spec.sh traces).                                               *)
EXTENDS Json, SignalConn, TLC

CONSTANTS TraceFile, W, R

Log == SelectSeq(ndJsonDeserialize(TraceFile),
    LAMBDA e : (e.sc = W /\ e.op \in {"write", "join", "drop"}) \/ (e.sc = R /\ e.op \in {"recv", "drop"}))
TraceN == LET ws == {Log[n].seq : n \in {m \in DOMAIN Log : Log[m].op = "write"}}
          IN IF ws = {} THEN 0 ELSE CHOOSE x \in ws : \A y \in ws : x >= y

\* A path's id (the order it was added in) is the spec's path.
P(id) == IF id = 0 THEN "relay" ELSE "direct"

VARIABLE l
E == Log[l]

TWrite ==
    /\ Write
    /\ sent' = E.seq
    /\ \A p \in Paths : Live(p) => \E i \in DOMAIN E.paths : P(E.paths[i]) = p

TJoin == IF E.path = 0 THEN UNCHANGED vars ELSE Join

TRecv == Recv(P(E.path)) /\ Head(chan[P(E.path)]) = E.seq

TDrop == IF dead[P(E.path)] THEN UNCHANGED vars ELSE Break(P(E.path))

Step ==
    CASE E.op = "write" -> TWrite
      [] E.op = "join" -> TJoin
      [] E.op = "recv" -> TRecv
      [] E.op = "drop" -> TDrop
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

TraceInit == Init /\ l = 1
TraceNext == l <= Len(Log) /\ Step /\ l' = l + 1

\* Violated once every line was taken: the trace is a behaviour.
TraceNotDone == l <= Len(Log)
=============================================================================
