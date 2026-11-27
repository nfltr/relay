--------------------------- MODULE TraceGroupIssuer ---------------------------
(* Trace check (spec/onegroup/README.md "Traces"): the issuer's steps as the *)
(* code recorded them (org/orgpki -tags enroltrace: trace_on.go,             *)
(* GROUPTRACE=<dir>), one JSON line each, under the issuer's lock:           *)
(*   issue  organisation o certified name n's serial s in groups gs, until  *)
(*          exp (GroupIssuer.tla Renew; an enrolment's first)               *)
(*   move   ... applied the root's order moving n at serial s into gs      *)
(*          (Apply)                                                         *)
(*   crl    ... signed CRL num listing serials rev at t (CRL)               *)
(*   sign   ... signed a status with CRL num and each member's groups and  *)
(*          newest serial, map (Sign)                                       *)
(* Read in order, each line must keep GroupIssuer.tla's properties as far  *)
(* as the issuer's lines show them: a certificate carries its name's       *)
(* groups at its issue (IssueInMap: a renewal or a rebind after a move     *)
(* takes the new groups), an order's serial is moved once (AppliedOnce),   *)
(* a CRL lists every unexpired serial a move revoked (CRLListsMoved), and  *)
(* a status shows the issuer's groups and is signed with a CRL listing     *)
(* every unexpired certificate of a member in other groups                 *)
(* (StatusWithItsCRL). The serials of one name are those its issue lines   *)
(* named. TraceDone is violated when every line was read: accepted.        *)
EXTENDS Integers, Sequences, FiniteSets, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, gr, cert, mv, crl, bad

vars == <<l, gr, cert, mv, crl, bad>>

Range(s) == {s[i] : i \in DOMAIN s}

Init ==
    /\ l = 1
    /\ gr = [x \in {} |-> {}]     \* <<o, n>> -> the issuer's groups of n
    /\ cert = [x \in {} |-> 0]    \* <<o, s>> -> [n, gs, exp]
    /\ mv = {}                    \* <<o, s>>: serials a move revoked
    /\ crl = [x \in {} |-> {}]    \* <<o, num>> -> the serials it lists
    /\ bad = {}

E == Log[l]
Key(x) == <<E.o, x>>
Serials(n) == {k[2] : k \in {k \in DOMAIN cert : k[1] = E.o /\ cert[k].n = n}}
Listed(num) == IF Key(num) \in DOMAIN crl THEN crl[Key(num)] ELSE {}
Live(s) == cert[Key(s)].exp > E.t

Bad ==
    CASE ~(E.ev \in {"issue", "move", "crl", "sign"}) -> {"diverged"}
      [] E.ev = "issue" ->
            IF Key(E.n) \in DOMAIN gr /\ Range(E.gs) # gr[Key(E.n)] THEN {"issue-stale"} ELSE {}
      [] E.ev = "move" ->
            (IF Key(E.s) \in mv THEN {"replayed"} ELSE {})
            \cup (IF E.s \notin Serials(E.n) THEN {"diverged"} ELSE {})
      [] E.ev = "crl" ->
            IF \E k \in mv : k[1] = E.o /\ Live(k[2]) /\ k[2] \notin Range(E.rev) THEN {"crl-misses-move"} ELSE {}
      [] OTHER ->
            UNION {(IF Key(n) \in DOMAIN gr /\ Range(E.map[n].gs) # gr[Key(n)] THEN {"status-not-map"} ELSE {})
                   \cup (IF \E s \in Serials(n) : Live(s) /\ cert[Key(s)].gs # Range(E.map[n].gs) /\ s \notin Listed(E.num)
                         THEN {"status-before-crl"} ELSE {})
                   : n \in DOMAIN E.map}

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ gr' = CASE E.ev = "issue" /\ Key(E.n) \notin DOMAIN gr -> (Key(E.n) :> Range(E.gs)) @@ gr
               [] E.ev = "move" -> (Key(E.n) :> Range(E.gs)) @@ gr
               [] OTHER -> gr
    /\ cert' = IF E.ev = "issue" THEN (Key(E.s) :> [n |-> E.n, gs |-> Range(E.gs), exp |-> E.exp]) @@ cert ELSE cert
    /\ mv' = IF E.ev = "move" THEN mv \cup {Key(s) : s \in Serials(E.n)} ELSE mv
    /\ crl' = IF E.ev = "crl" THEN (Key(E.num) :> Range(E.rev)) @@ crl ELSE crl
    /\ bad' = bad \cup {<<b, l>> : b \in Bad}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged"})
IssueInMap == None({"issue-stale"})
AppliedOnce == None({"replayed"})
CRLListsMoved == None({"crl-misses-move"})
StatusWithItsCRL == None({"status-before-crl", "status-not-map"})
TraceDone == l <= Len(Log)
=============================================================================
