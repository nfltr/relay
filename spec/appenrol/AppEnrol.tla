---------------------------- MODULE AppEnrol ----------------------------
\* An app's device enrolled for a person into an organisation
\* (spec/appenrol/README.md; nfltr docs/decisions/app-device-identity-2026-11-16.md).
\*
\* The organisation's issuer (org/orgenrol) certifies one key per app per
\* device: a name (a device slot), the person (an rfc822Name SAN) and the
\* app (URI SAN nfltr://<org>.internal/app/<id>). It enrols a key in one of
\* two ways: an admin code made for a person and an app (single use, as an
\* organisation token), or the person's sign-in at the organisation's IdP
\* (OIDC authorization code + PKCE): the ID token's nonce commits to the
\* device's keys, so a token certifies only the key its nonce names. A key
\* enrolled by sign-in renews by itself only until its sign-in ends
\* (authUntil = sign-in + AuthLife); then the person signs in again on that
\* device (Reauth), which the IdP refuses once it disabled the person.
\* Revoking a person or an app lists every live serial of every name it
\* holds and refuses its enrolments from then on. How a CRL reaches the
\* verifiers is spec/enrol/Enrol.tla's (here "listed" is the end of it);
\* who can forge or replay what over the relay is spec/proverif/app_enrol.pv.
\*
\* The attacker owns the relay: it sees every ID token and request, and
\* presents any token it saw with any key (its own, Kx). Time is a
\* discrete clock; a certificate lives CertLife ticks, a token TokLife.
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Users,      \* people
    Apps,       \* app ids
    HKeys,      \* keys honest devices make (one per app per device)
    Kx,         \* the attacker's key
    Names,      \* device slots the issuer names
    CodeIds,    \* admin codes the owner may make
    MaxTime,    \* clock bound
    CertLife,   \* a certificate's lifetime
    TokLife,    \* an ID token's lifetime
    AuthLife,   \* how long a sign-in lets a key renew by itself
    MaxCerts,   \* certificates issued (state bound)
    MaxToks,    \* ID tokens the IdP issues (state bound)
    Mutant

Keys == HKeys \cup {Kx}
NoTime == -1
Never == MaxTime + CertLife + AuthLife + TokLife + 1  \* a code-enrolled key's authUntil

VARIABLES
    now,
    idp,        \* idp[u]: "active" or "disabled" at the IdP
    disabledAt, \* when the IdP disabled u, NoTime if not
    toks,       \* ID tokens the IdP issued, not yet expired: [user, app, key, exp]
    signed,     \* history: every sign-in [user, app, key] the IdP saw
    codes,      \* codes[c]: [minted, user, app, used]: admin code c, redeemed used times
    enr,        \* enr[n]: [st, via, user, app, key, authUntil]
    certs,      \* certificates not yet expired: [name, user, app, key, na, rev]; rev: the issuer's CRL lists it
    nserial,    \* certificates issued (state bound)
    denyU,      \* revoked people
    denyA,      \* revoked apps
    reauths     \* sign-ins taken by Reauth (witness)

vars == <<now, idp, disabledAt, toks, signed, codes, enr, certs, nserial, denyU, denyA, reauths>>

Empty == [st |-> "none", via |-> "none", user |-> "none", app |-> "none", key |-> "none", authUntil |-> 0]

TypeOK ==
    /\ now \in 0..MaxTime
    /\ idp \in [Users -> {"active", "disabled"}]
    /\ \A n \in Names : enr[n].st \in {"none", "live", "revoked"}
    /\ \A c \in certs : c.na >= now /\ c.rev \in BOOLEAN
    /\ nserial \in 0..MaxCerts
    /\ denyU \subseteq Users /\ denyA \subseteq Apps

Init ==
    /\ now = 0
    /\ idp = [u \in Users |-> "active"]
    /\ disabledAt = [u \in Users |-> NoTime]
    /\ toks = {}
    /\ signed = {}
    /\ codes = [c \in CodeIds |-> [minted |-> FALSE, user |-> "none", app |-> "none", used |-> 0]]
    /\ enr = [n \in Names |-> Empty]
    /\ certs = {}
    /\ nserial = 0
    /\ denyU = {} /\ denyA = {}
    /\ reauths = FALSE

CanIssue == nserial < MaxCerts
NewCert(n, u, a, k) == [name |-> n, user |-> u, app |-> a, key |-> k, na |-> now + CertLife, rev |-> FALSE]
Issue(c) == certs' = certs \cup {c} /\ nserial' = nserial + 1
Live(c) == ~c.rev
LiveCertOf(n) == \E c \in certs : c.name = n /\ Live(c)
\* The issuer answers a key it already enrolled with that name again
\* (its answer lost); a key is never under two names.
NameOfKey(k) == {n \in Names : enr[n].st # "none" /\ enr[n].key = k}

\* Time passes; certificates past NotAfter and tokens past exp are dropped
\* (state bound: nothing below depends on them).
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ certs' = {c \in certs : c.na >= now + 1}
    /\ toks' = {t \in toks : t.exp >= now + 1 \/ Mutant = "no-token-exp"}
    /\ UNCHANGED <<idp, disabledAt, signed, codes, enr, nserial, denyU, denyA, reauths>>

\* The person signs in for app a on the device holding k; the nonce of
\* the ID token commits to k. Only an honest device starts a sign-in.
Login(u, a, k) ==
    /\ idp[u] = "active"
    /\ k \in HKeys
    /\ Cardinality(toks) < MaxToks
    /\ toks' = toks \cup {[user |-> u, app |-> a, key |-> k, exp |-> now + TokLife]}
    /\ signed' = signed \cup {[user |-> u, app |-> a, key |-> k]}
    /\ UNCHANGED <<now, idp, disabledAt, codes, enr, certs, nserial, denyU, denyA, reauths>>

DisableAtIdP(u) ==
    /\ idp[u] = "active"
    /\ idp' = [idp EXCEPT ![u] = "disabled"]
    /\ disabledAt' = [disabledAt EXCEPT ![u] = now]
    /\ UNCHANGED <<now, toks, signed, codes, enr, certs, nserial, denyU, denyA, reauths>>

\* The owner makes an admin code for person u and app a.
MintCode(c, u, a) ==
    /\ ~codes[c].minted
    /\ u \notin denyU /\ a \notin denyA
    /\ codes' = [codes EXCEPT ![c] = [minted |-> TRUE, user |-> u, app |-> a, used |-> 0]]
    /\ UNCHANGED <<now, idp, disabledAt, toks, signed, enr, certs, nserial, denyU, denyA, reauths>>

Fresh(n) == enr[n].st = "none"

\* A request (token t, key k) reaches the issuer: an honest device's, or
\* the relay's with a token it saw and any key.
EnrolSSO(t, k, n) ==
    /\ t \in toks
    /\ CanIssue
    /\ now <= t.exp
    /\ (Mutant = "no-nonce-check" \/ k = t.key)
    /\ (Mutant = "sso-skips-deny" \/ (t.user \notin denyU /\ t.app \notin denyA))
    /\ NameOfKey(k) = {}
    /\ Fresh(n)
    /\ enr' = [enr EXCEPT ![n] = [st |-> "live", via |-> "sso", user |-> t.user, app |-> t.app, key |-> k, authUntil |-> now + AuthLife]]
    /\ Issue(NewCert(n, t.user, t.app, k))
    /\ UNCHANGED <<now, idp, disabledAt, toks, signed, codes, denyU, denyA, reauths>>

EnrolCode(c, k, n) ==
    /\ k \in HKeys      \* a code reaches only its device (enrol.pv: the relay cannot use it)
    /\ codes[c].minted
    /\ CanIssue
    /\ (Mutant = "reusable-code" \/ codes[c].used = 0)
    /\ codes[c].user \notin denyU /\ codes[c].app \notin denyA
    /\ NameOfKey(k) = {}
    /\ Fresh(n)
    /\ codes' = [codes EXCEPT ![c].used = @ + 1]
    /\ enr' = [enr EXCEPT ![n] = [st |-> "live", via |-> "code", user |-> codes[c].user, app |-> codes[c].app, key |-> k, authUntil |-> Never]]
    /\ Issue(NewCert(n, codes[c].user, codes[c].app, k))
    /\ UNCHANGED <<now, idp, disabledAt, toks, signed, denyU, denyA, reauths>>

\* Renewal with the current key: the name's attributes, never the
\* request's (u, a: what a renewal request could claim).
Renew(n, u, a) ==
    /\ enr[n].st = "live"
    /\ CanIssue
    /\ LiveCertOf(n)
    /\ (Mutant = "renew-ignores-auth" \/ now <= enr[n].authUntil)
    /\ IF Mutant = "renew-takes-attrs"
       THEN Issue(NewCert(n, u, a, enr[n].key))
       ELSE Issue(NewCert(n, enr[n].user, enr[n].app, enr[n].key))
    /\ UNCHANGED <<now, idp, disabledAt, toks, signed, codes, enr, denyU, denyA, reauths>>

\* The person signs in again on the device: a token whose nonce names the
\* name's key and whose subject is the name's person extends authUntil.
Reauth(n, t) ==
    /\ enr[n].st = "live" /\ enr[n].via = "sso"
    /\ t \in toks
    /\ CanIssue
    /\ (Mutant = "no-token-exp" \/ now <= t.exp)
    /\ t.key = enr[n].key
    /\ (Mutant = "reauth-any-user" \/ (t.user = enr[n].user /\ t.app = enr[n].app))
    /\ t.user \notin denyU
    /\ enr' = [enr EXCEPT ![n].authUntil = now + AuthLife]
    /\ Issue(NewCert(n, enr[n].user, enr[n].app, enr[n].key))
    /\ reauths' = TRUE
    /\ UNCHANGED <<now, idp, disabledAt, toks, signed, codes, denyU, denyA>>

\* Revoke a person (or an app): every name of it, every live serial.
RevokeBy(ns) ==
    /\ enr' = [n \in Names |-> IF n \in ns THEN [enr[n] EXCEPT !.st = "revoked"] ELSE enr[n]]
    /\ certs' = {IF c.name \in ns THEN [c EXCEPT !.rev = TRUE] ELSE c : c \in certs}

RevokeUser(u) ==
    /\ u \notin denyU
    /\ denyU' = denyU \cup {u}
    /\ LET all == {n \in Names : enr[n].st = "live" /\ enr[n].user = u}
       IN IF Mutant = "revoke-user-one-name" /\ all # {}
          THEN \E n \in all : RevokeBy({n})
          ELSE RevokeBy(all)
    /\ UNCHANGED <<now, idp, disabledAt, toks, signed, codes, nserial, denyA, reauths>>

RevokeApp(a) ==
    /\ a \notin denyA
    /\ denyA' = denyA \cup {a}
    /\ LET all == {n \in Names : enr[n].st = "live" /\ enr[n].app = a /\ (Mutant # "revoke-app-sso-only" \/ enr[n].via = "sso")}
       IN RevokeBy(all)
    /\ UNCHANGED <<now, idp, disabledAt, toks, signed, codes, nserial, denyU, reauths>>

Next ==
    \/ Tick
    \/ \E u \in Users, a \in Apps, k \in HKeys : Login(u, a, k)
    \/ \E u \in Users : DisableAtIdP(u) \/ RevokeUser(u)
    \/ \E c \in CodeIds, u \in Users, a \in Apps : MintCode(c, u, a)
    \/ \E t \in toks, k \in Keys, n \in Names : EnrolSSO(t, k, n)
    \/ \E c \in CodeIds, k \in Keys, n \in Names : EnrolCode(c, k, n)
    \/ \E n \in Names : \E u \in (IF Mutant = "renew-takes-attrs" THEN Users ELSE {enr[n].user}),
                           a \in (IF Mutant = "renew-takes-attrs" THEN Apps ELSE {enr[n].app}) : Renew(n, u, a)
    \/ \E n \in Names, t \in toks : Reauth(n, t)
    \/ \E a \in Apps : RevokeApp(a)

Spec == Init /\ [][Next]_vars

\* ---- invariants ----

\* Every certificate carries the person, app and key its name was enrolled
\* with: renewals and sign-ins never change them.
AttrsFixed ==
    \A c \in certs : c.user = enr[c.name].user /\ c.app = enr[c.name].app /\ c.key = enr[c.name].key

\* A key enrolled by sign-in is one the person's own sign-in named, for
\* that app: the relay cannot attach its key to a token it saw.
SignInBindsKey ==
    \A n \in Names : enr[n].via = "sso" =>
        [user |-> enr[n].user, app |-> enr[n].app, key |-> enr[n].key] \in signed

\* Each admin code enrols at most one name.
CodeOnce == \A c \in CodeIds : codes[c].used <= 1

\* Once the IdP disabled a person, no certificate of a key enrolled by
\* sign-in outlives TokLife + AuthLife + CertLife after it.
DisabledUserBound ==
    \A c \in certs :
        (enr[c.name].via = "sso" /\ disabledAt[c.user] # NoTime) =>
            c.na <= disabledAt[c.user] + TokLife + AuthLife + CertLife

\* A revoked person or app holds no live, unlisted certificate.
RevokedUserCut == \A c \in certs : c.user \in denyU => c.rev
RevokedAppCut == \A c \in certs : c.app \in denyA => c.rev

\* ---- witnesses (each must be violated: the state is reachable) ----
WitnessSSOEnrol == ~\E n \in Names : enr[n].via = "sso"
WitnessCodeEnrol == ~\E n \in Names : enr[n].via = "code"
WitnessRenewed == ~\E c1, c2 \in certs : c1.name = c2.name /\ c1.na < c2.na /\ enr[c1.name].via = "code"
WitnessReauth == ~reauths
\* the residual the bound states: a disabled person's certificate still live
WitnessDisabledStillLive == ~\E c \in certs : disabledAt[c.user] # NoTime /\ disabledAt[c.user] < now /\ Live(c)
WitnessUserRevoked == ~\E c \in certs : c.user \in denyU /\ c.rev
WitnessAppRevoked == ~\E c \in certs : c.app \in denyA /\ c.rev
Sym == Permutations(Users) \cup Permutations(HKeys) \cup Permutations(Names)
=============================================================================
