----------------------------- MODULE TraceEnrol -----------------------------
(* Trace check (spec/enrol/README.md "Traces"): the steps of the issuer and *)
(* of verifiers that org/orgpki and the relay client's     *)
(* orgid recorded (-tags enroltrace: trace_on.go), one JSON line per step,  *)
(* read in order:                                                           *)
(*   issue   the issuer certified serial s of name n until exp; from: the    *)
(*           serial it renewed, "" for an enrolment (Enrol.tla Issue)        *)
(*   refuse  it refused to renew serial from: why log, expired, revoked, or  *)
(*           other (a signature, the CSR: outside the model)                 *)
(*   revoke  the owner revoked name n (Revoke)                               *)
(*   crl     the issuer signed CRL num, NextUpdate next, listing rev         *)
(*           (Revoke, Republish)                                             *)
(*   take    verifier v took (ok) or refused issuer k's CRL (Take, Fetch,    *)
(*           Replay)                                                         *)
(*   rotate  verifier v took a rotation: its CRLs are gone (TakeRoot)        *)
(*   check   verifier v admitted (ok) or refused serial s of issuer k, which *)
(*           expires at exp (Admit; a held session's re-check)               *)
(* Times are Unix seconds. Each line's outcome must be the one Enrol.tla's  *)
(* rules give from what the lines before it established (Conforms): the     *)
(* issuer's log as the trace saw it, and each verifier's CRLs. A wrong       *)
(* outcome that a model mutant names is reported by that mutant's property; *)
(* refusals for reasons outside the model (chain, name, group, other) are   *)
(* allowed. TraceDone is violated when every line was read: accepted.       *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, certs, revoked, last, held, bad

vars == <<l, certs, revoked, last, held, bad>>

Init ==
    /\ l = 1
    /\ certs = [x \in {} |-> 0]    \* <<org, serial>> -> [n, exp]
    /\ revoked = {}                \* <<org, name>>
    /\ last = [x \in {} |-> 0]     \* org -> its last CRL number
    /\ held = [x \in {} |-> 0]     \* <<verifier, issuer key>> -> [num, next, rev]
    /\ bad = {}

E == Log[l]
Set(sq) == {sq[i] : i \in DOMAIN sq}

\* issue, refuse: the serial renewed, as the trace knows it.
InLog == <<E.o, E.from>> \in DOMAIN certs
From == certs[<<E.o, E.from>>]
IsRevoked(o, n) == <<o, n>> \in revoked
RenewOK == InLog /\ From.n = E.n /\ From.exp > E.t /\ ~IsRevoked(E.o, E.n)
IssueBad ==
    CASE E.from = "" -> {}                              \* an enrolment: enrol.pv's
      [] ~InLog -> {"renew-forged"}
      [] IsRevoked(E.o, E.n) -> {"renew-revoked"}
      [] OTHER -> IF RenewOK THEN {} ELSE {"diverged"}
RefuseBad ==
    CASE E.why \in {"log", "other"} -> {}
      [] E.why = "expired" -> IF InLog /\ From.exp <= E.t THEN {} ELSE {"diverged"}
      [] E.why = "revoked" -> IF InLog /\ IsRevoked(E.o, E.n) THEN {} ELSE {"diverged"}
      [] OTHER -> {"diverged"}

\* crl: every unexpired serial of every revoked name (Enrol.tla Revoke).
Listable == {x[2] : x \in {c \in DOMAIN certs : c[1] = E.o /\ IsRevoked(E.o, certs[c].n) /\ certs[c].exp > E.t}}
CrlBad ==
    (IF Set(E.rev) = Listable THEN {}
     ELSE IF Set(E.rev) \subseteq Listable THEN {"revoke-current-only"} ELSE {"diverged"})
    \cup (IF E.o \in DOMAIN last /\ E.num <= last[E.o] THEN {"diverged"} ELSE {})
    \cup (IF E.next > E.t THEN {} ELSE {"diverged"})

\* take, check: verifier v's CRL of issuer k.
HK == <<E.v, E.k>>
Held == HK \in DOMAIN held
TakeOK == (~Held \/ E.num > held[HK].num) /\ E.next > E.t
TakeBad ==
    CASE E.ok /\ ~TakeOK -> IF E.next <= E.t THEN {"fail-open"} ELSE {"accept-older-crl"}
      [] ~E.ok /\ TakeOK -> {"diverged"}
      [] OTHER -> {}
CheckOK == E.exp > E.t /\ Held /\ held[HK].next > E.t /\ E.s \notin held[HK].rev
CheckBad ==
    CASE E.ok /\ ~CheckOK ->
            IF E.exp <= E.t THEN {"admit-expired"}
            ELSE IF ~Held \/ held[HK].next <= E.t THEN {"fail-open"}
            ELSE {"revoked-admitted"}
      [] ~E.ok /\ CheckOK -> IF E.why \in {"chain", "name", "group"} THEN {} ELSE {"diverged"}
      [] OTHER -> {}

Kinds == {"issue", "refuse", "revoke", "crl", "take", "rotate", "check"}

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ certs' = IF E.ev = "issue" THEN (<<E.o, E.s>> :> [n |-> E.n, exp |-> E.exp]) @@ certs ELSE certs
    /\ revoked' = IF E.ev = "revoke" THEN revoked \cup {<<E.o, E.n>>} ELSE revoked
    /\ last' = IF E.ev = "crl" THEN (E.o :> E.num) @@ last ELSE last
    /\ held' = CASE E.ev = "take" /\ E.ok -> (HK :> [num |-> E.num, next |-> E.next, rev |-> Set(E.rev)]) @@ held
                 [] E.ev = "rotate" -> [x \in {y \in DOMAIN held : y[1] # E.v} |-> held[x]]
                 [] OTHER -> held
    /\ bad' = bad \cup {<<b, l>> : b \in
                CASE E.ev \notin Kinds -> {"diverged"}
                  [] E.ev = "issue" -> IssueBad
                  [] E.ev = "refuse" -> RefuseBad
                  [] E.ev = "revoke" -> IF \E c \in DOMAIN certs : c[1] = E.o /\ certs[c].n = E.n THEN {} ELSE {"diverged"}
                  [] E.ev = "crl" -> CrlBad
                  [] E.ev = "take" -> TakeBad
                  [] E.ev = "check" -> CheckBad
                  [] OTHER -> {}}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged"})
NoRenewAfterRevoke == None({"renew-revoked"})
ForgedOnlyUnderStolenRoot == None({"renew-forged"})
RevokedMachineRefused == None({"accept-older-crl", "revoked-admitted", "revoke-current-only"})
RevocationBound == None({"fail-open"})
NoExpiredSession == None({"admit-expired"})
TraceDone == l <= Len(Log)
=============================================================================
