---------------------------- MODULE TraceGrant ----------------------------
(* Trace check (spec/grant/README.md "Traces"): the grant steps of the     *)
(* issuer (relay org/orgpki grant.go, issuer.go) and of the serving        *)
(* agent's check (client/orgid grant.go) that the tests write with -tags   *)
(* enroltrace (GRANTTRACE=<dir>), one JSON line each, in the order they    *)
(* happened in the test process (each writer under its lock, one write a   *)
(* line), keyed by organisation o:                                         *)
(*   req     request id by who for where/svc, d seconds (Grant.tla Request) *)
(*   sign    grant sn of request id for who, where/svc, until, approved by  *)
(*           by, whom the root's policy names approvers ap of it (Sign)     *)
(*   deny    request id denied by by (Deny)                                 *)
(*   revoke  grant sn revoked (Revoke)                                      *)
(*   crl     the issuer's CRL num, next, listing the grant serials rev      *)
(*           (Publish)                                                      *)
(*   admit   the agent's check of grant sn (who, where/svc, until) for a    *)
(*           client cwho opening one of svcs at t, holding CRL num (its     *)
(*           next, rev: whether it lists sn): ok, and the admission's end u *)
(*           (Deliver, Open, Tick: the session's timer is u)                *)
(* Times are Unix seconds. Each line must be what Grant.tla allows given    *)
(* the lines before it; a wrong step that a model mutant names is reported  *)
(* by that mutant's property, any other by Conforms. TraceDone is violated *)
(* when every line was read: accepted.                                      *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, reqs, grants, crls, bad

vars == <<l, reqs, grants, crls, bad>>

Init ==
    /\ l = 1
    /\ reqs = [x \in {} |-> 0]    \* <<o, id>> -> [who, where, svc, d, st: open|granted|denied]
    /\ grants = [x \in {} |-> 0]  \* <<o, sn>> -> [who, where, svc, until, rev]
    /\ crls = [x \in {} |-> 0]    \* <<o, num>> -> the set of serials it lists
    /\ bad = {}

E == Log[l]
Set(sq) == {sq[i] : i \in DOMAIN sq}
RK == <<E.o, E.id>>
GK == <<E.o, E.sn>>
R == reqs[RK]

SignBad ==
    IF RK \notin DOMAIN reqs THEN {"diverged"}
    ELSE (IF R.st = "denied" THEN {"issuer-signs-denied"} ELSE IF R.st # "open" THEN {"issuer-no-replay-set"} ELSE {})
         \cup (IF E.who = R.who /\ E.where = R.where /\ E.svc = R.svc THEN {} ELSE {"widened"})
         \cup (IF E.until <= E.t + R.d THEN {} ELSE {"dur-from-request"})
         \cup (IF E.by \in Set(E.ap) THEN {} ELSE {"issuer-any-approver"})
         \cup (IF E.who # "person:" \o E.by THEN {} ELSE {"self-approve"})
         \cup (IF GK \in DOMAIN grants THEN {"diverged"} ELSE {})

DenyBad == IF RK \in DOMAIN reqs /\ R.st = "open" THEN {} ELSE {"diverged"}

RevokeBad == IF GK \in DOMAIN grants /\ ~grants[GK].rev THEN {} ELSE {"diverged"}

\* Every grant revoked before, not ended, is listed; nothing else is.
Due == {k[2] : k \in {x \in DOMAIN grants : x[1] = E.o /\ grants[x].rev /\ E.t < grants[x].until}}
CrlBad ==
    (IF Due \subseteq Set(E.rev) THEN {} ELSE {"revoke-not-listed"})
    \cup (IF \A s \in Set(E.rev) : <<E.o, s>> \in DOMAIN grants /\ grants[<<E.o, s>>].rev THEN {} ELSE {"diverged"})

Known == GK \in DOMAIN grants
CK == <<E.o, E.num>>
AdmitBad ==
    IF ~E.ok THEN {}
    ELSE (IF E.who = E.cwho THEN {} ELSE {"agent-any-principal"})
         \cup (IF E.svc \in Set(E.svcs) THEN {} ELSE {"agent-any-service"})
         \cup (IF E.t < E.until THEN {} ELSE {"agent-no-expiry-check"})
         \cup (IF E.u <= E.until THEN {} ELSE {"expiry-refuses-only"})
         \cup (IF E.num > 0 /\ ~E.rev /\ (CK \in DOMAIN crls => E.sn \notin crls[CK]) THEN {} ELSE {"agent-no-rev-check"})
         \cup (IF E.t < E.next THEN {} ELSE {"stale-list-admits"})
         \cup (IF E.u <= E.next THEN {} ELSE {"stale-list-keeps"})
         \cup (IF ~Known \/ (grants[GK].who = E.who /\ grants[GK].where = E.where /\ grants[GK].svc = E.svc /\ grants[GK].until = E.until)
               THEN {} ELSE {"diverged"})

Kinds == {"req", "sign", "deny", "revoke", "crl", "admit"}

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ reqs' = CASE E.ev = "req" -> (RK :> [who |-> E.who, where |-> E.where, svc |-> E.svc, d |-> E.d, st |-> "open"]) @@ reqs
                 [] E.ev = "sign" /\ RK \in DOMAIN reqs -> [reqs EXCEPT ![RK].st = "granted"]
                 [] E.ev = "deny" /\ RK \in DOMAIN reqs -> [reqs EXCEPT ![RK].st = "denied"]
                 [] OTHER -> reqs
    /\ grants' = CASE E.ev = "sign" -> (GK :> [who |-> E.who, where |-> E.where, svc |-> E.svc, until |-> E.until, rev |-> FALSE]) @@ grants
                   [] E.ev = "revoke" /\ Known -> [grants EXCEPT ![GK].rev = TRUE]
                   [] OTHER -> grants
    /\ crls' = IF E.ev = "crl" THEN (<<E.o, E.num>> :> Set(E.rev)) @@ crls ELSE crls
    /\ bad' = bad \cup {<<b, l>> : b \in
                CASE E.ev \notin Kinds -> {"diverged"}
                  [] E.ev = "req" -> (IF RK \in DOMAIN reqs THEN {"diverged"} ELSE {})
                  [] E.ev = "sign" -> SignBad
                  [] E.ev = "deny" -> DenyBad
                  [] E.ev = "revoke" -> RevokeBad
                  [] E.ev = "crl" -> CrlBad
                  [] E.ev = "admit" -> AdmitBad
                  [] OTHER -> {}}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged"})
GrantedOnly == None({"agent-any-principal", "agent-any-service"})
ExpiryBound == None({"agent-no-expiry-check", "expiry-refuses-only"})
RevokeBound == None({"agent-no-rev-check", "stale-list-admits", "stale-list-keeps", "revoke-not-listed"})
ApprovalOnce == None({"issuer-no-replay-set"})
GrantMatchesApproval == None({"widened", "dur-from-request", "issuer-any-approver", "self-approve"})
DenyFinal == None({"issuer-signs-denied"})
TraceDone == l <= Len(Log)
=============================================================================
