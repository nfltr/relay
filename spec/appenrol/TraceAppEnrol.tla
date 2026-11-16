--------------------------- MODULE TraceAppEnrol ---------------------------
(* Trace check (spec/appenrol/README.md "Traces"): the issuer's steps that *)
(* org/orgpki recorded (-tags enroltrace, APPENROLTRACE=<dir>: trace_on.go *)
(* appTraceLine), one JSON line per step, read in order:                   *)
(*   sso     a sign-in enrolled (or certified again) name n for person u,   *)
(*           app a, key k: the token's nonce, the nonce of the request's    *)
(*           keys kn, the token's exp, the sign-in's end au (EnrolSSO,      *)
(*           Reauth)                                                        *)
(*   code    token tok enrolled name n for u, a, key k (EnrolCode; an       *)
(*           answer again: Join.tla's)                                      *)
(*   renew   name n renewed, the certificate for u, a, key k (Renew)        *)
(*   refuse  why: token (the ID token's check: go-oidc, outside the model), *)
(*           nonce, denied, revoked, code (a code-enrolled key), other      *)
(*           (another person's or app's key): a sign-in; auth: a renewal    *)
(*           past the sign-in's end                                         *)
(*   revoke  names revoked: one name, or every name of person u (app a)     *)
(*           (RevokeUser, RevokeApp)                                        *)
(* Times are Unix seconds. Each line must be what AppEnrol.tla's rules      *)
(* allow given the lines before it; a wrong step that a model mutant names  *)
(* is reported by that mutant's property, any other by Conforms. A name     *)
(* first seen in a renewal came from a replayed log (a move's import): it  *)
(* is taken as it is. TraceDone is violated when every line was read:       *)
(* accepted.                                                                *)
EXTENDS Integers, Sequences, TLC, Json

CONSTANT TraceFile

Log == ndJsonDeserialize(TraceFile)

VARIABLES l, enr, revoked, deny, codes, bad

vars == <<l, enr, revoked, deny, codes, bad>>

Init ==
    /\ l = 1
    /\ enr = [x \in {} |-> 0]      \* <<org, name>> -> [u, a, via, au, k]
    /\ revoked = {}                \* <<org, name>>
    /\ deny = {}                   \* <<org, "u", person>>, <<org, "a", app>>
    /\ codes = [x \in {} |-> ""]   \* <<org, token>> -> the name it enrolled
    /\ bad = {}

E == Log[l]
Set(sq) == {sq[i] : i \in DOMAIN sq}
NK == <<E.o, E.n>>
Known == NK \in DOMAIN enr
Cur == enr[NK]
DeniedU == E.u # "" /\ <<E.o, "u", E.u>> \in deny
DeniedA == E.a # "" /\ <<E.o, "a", E.a>> \in deny
DenyBad(mu, ma) == (IF DeniedU THEN {mu} ELSE {}) \cup (IF DeniedA THEN {ma} ELSE {})
SameAttrs == Cur.u = E.u /\ Cur.a = E.a

SsoBad ==
    (IF E.nonce # E.kn THEN {"no-nonce-check"} ELSE {})
    \cup DenyBad("sso-skips-deny", "sso-skips-deny-app")
    \cup (IF E.exp < E.t THEN {"no-token-exp"} ELSE {})
    \cup (IF ~Known THEN {}
          ELSE (IF Cur.via # "sso" THEN {"signin-takes-code-key"} ELSE {})
               \cup (IF SameAttrs THEN {} ELSE {"reauth-any-user"})
               \cup (IF Cur.k # E.k THEN {"diverged"} ELSE {})
               \cup (IF NK \in revoked THEN {"reauth-revoked"} ELSE {}))

CodeBad ==
    (IF <<E.o, E.tok>> \in DOMAIN codes /\ codes[<<E.o, E.tok>>] # E.n THEN {"reusable-code"} ELSE {})
    \cup DenyBad("sso-skips-deny", "sso-skips-deny-app")
    \cup (IF Known /\ ~SameAttrs THEN {"renew-takes-attrs"} ELSE {})

RenewBad ==
    IF ~Known THEN {}
    ELSE (IF SameAttrs THEN {} ELSE {"renew-takes-attrs"})
         \cup (IF Cur.via = "sso" /\ E.t > Cur.au THEN {"renew-ignores-auth"} ELSE {})
         \cup DenyBad("sso-skips-deny", "sso-skips-deny-app")

RefuseBad ==
    CASE E.why = "token" -> {}
      [] E.why = "nonce" -> IF E.nonce # E.kn THEN {} ELSE {"diverged"}
      [] E.why = "denied" -> IF DeniedU \/ DeniedA THEN {} ELSE {"diverged"}
      [] E.why = "revoked" -> IF Known /\ NK \in revoked THEN {} ELSE {"diverged"}
      [] E.why = "code" -> IF Known /\ Cur.via = "code" THEN {} ELSE {"diverged"}
      [] E.why = "other" -> IF Known /\ ~SameAttrs THEN {} ELSE {"diverged"}
      [] E.why = "auth" -> IF Known /\ Cur.via = "sso" /\ E.t > Cur.au THEN {} ELSE {"diverged"}
      [] OTHER -> {"diverged"}

\* revoke: every live name of the person (app) is listed.
Of(f, v) == {x[2] : x \in {y \in DOMAIN enr : y[1] = E.o /\ enr[y][f] = v /\ y \notin revoked}}
RevokeBad ==
    (IF E.u # "" /\ ~(Of("u", E.u) \subseteq Set(E.names)) THEN {"revoke-user-one-name"} ELSE {})
    \cup (IF E.a # "" /\ ~(Of("a", E.a) \subseteq Set(E.names)) THEN {"revoke-app-sso-only"} ELSE {})

Kinds == {"sso", "code", "renew", "refuse", "revoke"}
Via == IF E.ev = "sso" THEN "sso" ELSE IF Known THEN Cur.via ELSE "code"
Au == IF E.ev = "sso" THEN E.au ELSE IF Known THEN Cur.au ELSE 0

Next ==
    /\ l <= Len(Log) /\ l' = l + 1
    /\ enr' = IF E.ev \in {"sso", "code", "renew"}
              THEN (NK :> [u |-> E.u, a |-> E.a, via |-> Via, au |-> Au, k |-> E.k]) @@ enr
              ELSE enr
    /\ revoked' = IF E.ev = "revoke" THEN revoked \cup {<<E.o, x>> : x \in Set(E.names)} ELSE revoked
    /\ deny' = IF E.ev = "revoke"
               THEN deny \cup (IF E.u # "" THEN {<<E.o, "u", E.u>>} ELSE {}) \cup (IF E.a # "" THEN {<<E.o, "a", E.a>>} ELSE {})
               ELSE deny
    /\ codes' = IF E.ev = "code" /\ <<E.o, E.tok>> \notin DOMAIN codes THEN (<<E.o, E.tok>> :> E.n) @@ codes ELSE codes
    /\ bad' = bad \cup {<<b, l>> : b \in
                CASE E.ev \notin Kinds -> {"diverged"}
                  [] E.ev = "sso" -> SsoBad
                  [] E.ev = "code" -> CodeBad
                  [] E.ev = "renew" -> RenewBad
                  [] E.ev = "refuse" -> RefuseBad
                  [] E.ev = "revoke" -> RevokeBad
                  [] OTHER -> {}}

None(names) == \A b \in bad : b[1] \notin names
Conforms == None({"diverged", "reauth-revoked", "signin-takes-code-key"})
AttrsFixed == None({"renew-takes-attrs", "reauth-any-user"})
SignInBindsKey == None({"no-nonce-check"})
CodeOnce == None({"reusable-code"})
DisabledUserBound == None({"renew-ignores-auth", "no-token-exp"})
RevokedUserCut == None({"sso-skips-deny", "revoke-user-one-name"})
RevokedAppCut == None({"sso-skips-deny-app", "revoke-app-sso-only"})
TraceDone == l <= Len(Log)
=============================================================================
