---------------------------- MODULE TraceAuditLog ----------------------------
(* Trace validation of AuditLog.tla (spec/README.md "AuditLog and         *)
(* MoveAudit traces", lane SA5TRACE): the steps one machine directory's   *)
(* audit log took in a run (-tags audittrace, client/orgaudit             *)
(* trace_on.go), each logged under the log's lock, must be a behaviour of *)
(* AuditLog, in order. Logged: the owner file's listing (intent), the     *)
(* open and close lines with their seq (OpenLine, CloseLine: the line's   *)
(* index is its seq, one log), a refusal's line (refused, Refuse), the    *)
(* owner file's prune (forget), a                                         *)
(* recovering process's lost close of a gone owner's session (lost,       *)
(* Recover) and that owner file's deletion (recovered, RecoverDone), a    *)
(* test's kill (crash: the owner lock released), what the issuer          *)
(* acknowledged (ship: Rotate's acked, the seq of the line it ends at;    *)
(* the same again changes nothing) and the file's new first line          *)
(* (rotate). Not logged, so TLC adds it: a process's start. Accepted when *)
(* TLC reaches the trace's end: TraceUnfinished violated.                 *)
EXTENDS AuditLog, Json, TLC

CONSTANTS TraceFile

Log == ndJsonDeserialize(TraceFile)
Ids(f) == {Log[i][f] : i \in {j \in 1..Len(Log) : f \in DOMAIN Log[j]}}
TraceProcs == Ids("p") \cup Ids("q")
TraceSess == Ids("s")
TraceMaxRot == Cardinality({i \in 1..Len(Log) : Log[i].ev = "rotate"})
TraceMaxRef == Cardinality({i \in 1..Len(Log) : Log[i].ev = "refused"})

VARIABLE l
traceVars == <<vars, l>>

E == Log[l]
Wrote == Len(log') = E.seq

Step ==
    CASE E.ev = "intent" -> Intent(E.p, E.s)
      [] E.ev = "open" -> OpenLine(E.p, E.s) /\ Wrote
      [] E.ev = "close" -> CloseLine(E.p, E.s) /\ Wrote
      [] E.ev = "forget" -> Forget(E.p, E.s)
      [] E.ev = "refused" -> Refuse(E.p) /\ Wrote
      [] E.ev = "lost" -> Recover(E.p, E.q, E.s) /\ Wrote
      [] E.ev = "recovered" -> RecoverDone(E.p, E.q)
      [] E.ev = "crash" -> Crash(E.p)
      [] E.ev = "ship" -> IF E.seq = acked THEN UNCHANGED vars ELSE Ship(E.seq)
      [] E.ev = "rotate" -> \E p \in Procs : Rotate(p) /\ base' = E.seq
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

Env == \E p \in Procs : Start(p)

TraceInit == Init /\ l = 1
TraceNext == (l <= Len(Log) /\ Step /\ l' = l + 1) \/ (Env /\ UNCHANGED l)

\* Violated once every line was taken.
TraceUnfinished == l <= Len(Log)
=============================================================================
