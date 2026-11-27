---------------------------- MODULE TraceMoveAudit ----------------------------
(* Trace validation of MoveAudit.tla (spec/README.md "AuditLog and        *)
(* MoveAudit traces", lane SA5TRACE): one test process's steps (-tags     *)
(* 'enroltrace audittrace': the machine's lines from client/orgaudit      *)
(* trace_on.go, the issuer's from relay org internal/audittrace) must be  *)
(* a behaviour of MoveAudit, in order. Logged: a line the machine wrote   *)
(* (write, its seq), an issuer directory's intake of a post (take: h the  *)
(* directory, the machine's seq it held before and after, whether the     *)
(* checker found a gap), nfltr org move send's fence and bundle (fence,   *)
(* send) and receive's import. The hosts are the directories in the      *)
(* order the trace names them (host 1, the first, holds the organisation  *)
(* at first) and one more (a recipient not named yet). Whether a take's   *)
(* answer reached the machine is TLC's choice. Accepted when TLC reaches  *)
(* the trace's end: TraceUnfinished violated.                            *)
EXTENDS MoveAudit, Json, TLC, Sequences

CONSTANTS TraceFile

Log == ndJsonDeserialize(TraceFile)
Dirs == LET f[i \in 0..Len(Log)] ==
            IF i = 0 THEN <<>>
            ELSE IF "h" \notin DOMAIN Log[i] \/ \E j \in 1..Len(f[i - 1]) : f[i - 1][j] = Log[i].h
                 THEN f[i - 1]
                 ELSE Append(f[i - 1], Log[i].h)
        IN f[Len(Log)]
TraceNH == Len(Dirs) + 1
TraceMaxLines == Cardinality({i \in 1..Len(Log) : Log[i].ev = "write"})
Host(d) == CHOOSE i \in 1..Len(Dirs) : Dirs[i] = d

VARIABLE l
traceVars == <<vars, l>>

E == Log[l]

Step ==
    CASE E.ev = "write" -> Write /\ lines' = E.n
      [] E.ev = "take" -> LET h == Host(E.h) IN
            /\ dir[h] # None /\ dir[h].held = E.pre
            /\ \E n \in 1..MaxLines, a \in BOOLEAN : Take(h, n, a)
            /\ dir'[h].held = E.n /\ gap' = E.gap
      [] E.ev = "fence" -> \E r \in Hosts : Fence(Host(E.h), r)
      [] E.ev = "send" -> Send(Host(E.h))
      [] E.ev = "import" -> \E b \in bundles : Import(Host(E.h), b)
      [] OTHER -> Print(<<"unknown event", E>>, FALSE)

TraceInit == Init /\ l = 1
TraceNext == l <= Len(Log) /\ Step /\ l' = l + 1

\* Violated once every line was taken.
TraceUnfinished == l <= Len(Log)
=============================================================================
