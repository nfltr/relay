----------------------------- MODULE TraceEnrol -----------------------------
(* Trace check (spec/enrol/README.md "Traces"): the steps of the issuer and *)
(* of verifiers that org/orgpki and the relay client's     *)
(* orgid recorded (-tags enroltrace: trace_on.go), one JSON line per step,  *)
(* read in order:                                                           *)
(*   issue   the issuer certified serial s of name n until exp for key k;    *)
(*           from: the serial it renewed, "" for an enrolment by token tok   *)
(*           (Enrol.tla Issue; a token answered again: Join.tla Issue)       *)
(*   refuse  it refused to renew serial from: why log, expired, revoked,     *)
(*           rebound (a rebind retired it), or                               *)
(*           other (a signature, the CSR: outside the model); why enrolled:  *)
(*           an enrolment by token tok for key k (Join.tla Issue)            *)
(*   revoke  the owner revoked name n (Revoke)                               *)
(*   rebind  the issue line before it rebound name n to a new machine id:    *)
(*           every earlier serial of n is retired, s the new one (Rebind)    *)
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

VARIABLES l, certs, revoked, last, held, bad, tokkey, lastTok, retired, newest

vars == <<l, certs, revoked, last, held, bad, tokkey, lastTok, retired, newest>>

Init ==
    /\ l = 1
    /\ certs = [x \in {} |-> 0]    \* <<org, serial>> -> [n, exp]
    /\ revoked = {}                \* <<org, name>>
    /\ last = [x \in {} |-> 0]     \* org -> its last CRL number
    /\ held = [x \in {} |-> 0]     \* <<verifier, issuer key>> -> [num, next, rev]
    /\ bad = {}
    /\ tokkey = [x \in {} |-> ""]  \* <<org, token>> -> the key it enrolled
    /\ lastTok = [x \in {} |-> ""] \* <<org, name>> -> its newest certificate's token, "" a renewal
    /\ retired = {}                \* <<org, serial>>: retired by a rebind
    /\ newest = [x \in {} |-> ""]  \* <<org, name>> -> its newest serial

E == Log[l]
Set(sq) == {sq[i] : i \in DOMAIN sq}

\* issue, refuse: the serial renewed, as the trace knows it.
InLog == <<E.o, E.from>> \in DOMAIN certs
From == certs[<<E.o, E.from>>]
IsRevoked(o, n) == <<o, n>> \in revoked
\* Enrol.tla Renews: valid, or the name's newest within the grace
\* (orgpki.RenewGrace, a week in seconds).
RenewGrace == 604800
Renewable == From.exp > E.t \/ (From.exp + RenewGrace > E.t /\ <<E.o, From.n>> \in DOMAIN newest /\ newest[<<E.o, From.n>>] = E.from)
RenewOK == InLog /\ From.n = E.n /\ Renewable /\ ~IsRevoked(E.o, E.n)
\* An enrolment: a token's first is enrol.pv's; answered again (Join.tla
\* Reissues), only for the key it enrolled, of a name not revoked whose
\* newest certificate is still the token's.
TK == <<E.o, E.tok>>
NK == <<E.o, E.n>>
Redeemed == TK \in DOMAIN tokkey
TokensNewest == NK \in DOMAIN lastTok /\ lastTok[NK] = E.tok
\* (An enrolment by sign-in carries no token: spec/appenrol's.)
EnrolBad ==
    IF ~Redeemed \/ E.tok = "" THEN {}
    ELSE (IF E.k # tokkey[TK] THEN {"reissue-any-key"} ELSE {})
         \cup (IF IsRevoked(E.o, E.n) THEN {"renew-revoked"} ELSE {})
         \cup (IF TokensNewest THEN {} ELSE {"reissue-after-renewal"})
IssueBad ==
    CASE E.from = "" -> EnrolBad
      [] ~InLog -> {"renew-forged"}
      [] <<E.o, E.from>> \in retired -> {"renew-rebound"}
      [] IsRevoked(E.o, E.n) -> {"renew-revoked"}
      [] OTHER -> CASE RenewOK -> {}
                    [] InLog /\ From.n = E.n /\ From.exp + RenewGrace <= E.t -> {"renew-past-grace"}
                    [] InLog /\ From.n = E.n /\ From.exp <= E.t -> {"grace-any-serial"}
                    [] OTHER -> {"diverged"}
RefuseBad ==
    CASE E.why \in {"log", "other"} -> {}
      [] E.why = "enrolled" ->
            IF Redeemed /\ E.k = tokkey[TK] /\ ~IsRevoked(E.o, E.n) /\ TokensNewest THEN {"burn-name"} ELSE {}
      [] E.why = "expired" -> IF InLog /\ ~Renewable THEN {} ELSE {"diverged"}
      [] E.why = "revoked" -> IF InLog /\ IsRevoked(E.o, E.n) THEN {} ELSE {"diverged"}
      [] E.why = "rebound" -> IF <<E.o, E.from>> \in retired THEN {} ELSE {"diverged"}
      [] OTHER -> {"diverged"}

\* crl: every unexpired serial of every revoked name (Enrol.tla Revoke)
\* and every unexpired serial a rebind retired (Rebind).
Listable == {x[2] : x \in {c \in DOMAIN certs : c[1] = E.o /\ IsRevoked(E.o, certs[c].n) /\ certs[c].exp > E.t}}
ListRetired == {x[2] : x \in {c \in retired : c[1] = E.o /\ certs[c].exp > E.t}}
CrlBad ==
    (IF Set(E.rev) = Listable \cup ListRetired THEN {}
     ELSE IF ~(ListRetired \subseteq Set(E.rev)) THEN {"rebind-keeps-serials"}
     ELSE IF Set(E.rev) \subseteq Listable \cup ListRetired THEN {"revoke-current-only"} ELSE {"diverged"})
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
      [] ~E.ok /\ CheckOK -> IF E.why \in {"chain", "name", "group", "user", "app"} THEN {} ELSE {"diverged"}
      [] OTHER -> {}

\* itake (the root's CRL of issuers taken) is spec/orgmove/TraceOrgHosted.tla's.
Kinds == {"issue", "refuse", "revoke", "rebind", "crl", "take", "rotate", "check", "itake"}

\* rebind: the name's serials the trace knows, but the new one.
Retires == {c \in DOMAIN certs : c[1] = E.o /\ certs[c].n = E.n /\ c[2] # E.s}

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ certs' = IF E.ev = "issue" THEN (<<E.o, E.s>> :> [n |-> E.n, exp |-> E.exp]) @@ certs ELSE certs
    /\ revoked' = IF E.ev = "revoke" THEN revoked \cup {<<E.o, E.n>>} ELSE revoked
    /\ last' = IF E.ev = "crl" THEN (E.o :> E.num) @@ last ELSE last
    /\ tokkey' = IF E.ev = "issue" /\ E.from = "" /\ E.tok # "" /\ ~Redeemed THEN (TK :> E.k) @@ tokkey ELSE tokkey
    /\ lastTok' = IF E.ev = "issue" THEN (NK :> E.tok) @@ lastTok ELSE lastTok
    /\ retired' = IF E.ev = "rebind" THEN retired \cup Retires ELSE retired
    /\ newest' = IF E.ev = "issue" THEN (NK :> E.s) @@ newest ELSE newest
    /\ held' = CASE E.ev = "take" /\ E.ok -> (HK :> [num |-> E.num, next |-> E.next, rev |-> Set(E.rev)]) @@ held
                 [] E.ev = "rotate" -> [x \in {y \in DOMAIN held : y[1] # E.v} |-> held[x]]
                 [] OTHER -> held
    /\ bad' = bad \cup {<<b, l>> : b \in
                CASE E.ev \notin Kinds -> {"diverged"}
                  [] E.ev = "issue" -> IssueBad
                  [] E.ev = "refuse" -> RefuseBad
                  [] E.ev = "rebind" -> IF <<E.o, E.s>> \in DOMAIN certs /\ certs[<<E.o, E.s>>].n = E.n /\ ~IsRevoked(E.o, E.n) THEN {} ELSE {"diverged"}
                  [] E.ev = "revoke" -> IF \E c \in DOMAIN certs : c[1] = E.o /\ certs[c].n = E.n THEN {} ELSE {"diverged"}
                  [] E.ev = "crl" -> CrlBad
                  [] E.ev = "take" -> TakeBad
                  [] E.ev = "check" -> CheckBad
                  [] OTHER -> {}}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged"})
NoRenewAfterRevoke == None({"renew-revoked"})
OneKeyPerToken == None({"reissue-any-key"})
NoRetiredKeyRevived == None({"reissue-after-renewal"})
RefusedOnlyForCause == None({"burn-name"})
ForgedOnlyUnderStolenRoot == None({"renew-forged"})
NoRenewOfRetired == None({"renew-rebound"})
RetiredRefused == None({"rebind-keeps-serials"})
RevokedMachineRefused == None({"accept-older-crl", "revoked-admitted", "revoke-current-only"})
RevocationBound == None({"fail-open"})
NoExpiredSession == None({"admit-expired"})
NoRenewPastGrace == None({"renew-past-grace"})
GraceOnlyNewest == None({"grace-any-serial"})
TraceDone == l <= Len(Log)
=============================================================================
