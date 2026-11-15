----------------------------- MODULE Join -----------------------------
\* Enrolment by a single-use token over the relay's mailboxes
\* (spec/enrol/README.md "Join.tla"): a machine's `nfltr org join` posts a
\* request binding a key to the token (Start), the issuer answers it under
\* its lock when it reads it (Issue), and the join installs an answer for
\* its key (Install) or gives up waiting (GiveUp: the issuer was slow, its
\* answer may still come). The relay may lose a request or an answer
\* (Lose) and keeps the others. A join that gave up is run again with the
\* same token (Start again). Each run posts its request under an id of its
\* own (the relay keeps a sender's idempotency key a day, longer than an
\* answer) and reads the answer to it or to the first run's.
\*
\* The join keeps the key it made for the token (orgenrol's pending join
\* key) and asks again with it; the issuer answers a request for the key
\* the token enrolled again (a new certificate for that key) while the
\* name is not revoked and was not renewed since, and refuses any other
\* key (the token was redeemed). So a lost or late answer never burns the
\* name, and a token certifies one key only.
\*
\* The join takes the organisation's root from the relay: the pinned root
\* (generation 1, the one the token was made under) or a root the pinned
\* recovery key certifies (a rotation since: Rotate), as a running machine
\* takes a rotation; never an attacker's root (Evil, signed by another key).
\* The attacker may also hold the token (it leaked: Other) and the
\* machine's join key once a renewal retired it (Renew, then ReplayOld).
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxRoot,      \* the owner's root generations 1..MaxRoot (1: the pinned one)
    MaxTries,     \* join runs (state bound)
    MaxKeys,      \* keys the machine makes (state bound)
    MaxCerts,     \* certificates the issuer issues for the name (state bound)
    MaxLost,      \* requests or answers the relay loses
    Mutant

Evil == MaxRoot + 1   \* a root another key signed (the attacker's)
OtherKey == 0         \* the key of whoever else holds the token
Results == {"none", "joined", "refused-token", "refused-root"}

VARIABLES
    root,     \* the owner's current root generation
    certs,    \* the name's certificates in the issuer's log: <<[key, root, tok, afterRevoke]>>
    revoked,  \* the owner revoked the name
    other,    \* the token leaked: another key's request was posted
    replayed, \* the attacker posted the machine's retired join key (after a renewal)
    reqs,     \* requests the relay carries: [key, run] (run 0: not the machine's)
    ans,      \* answers it carries: [key, cert, run] (cert 0: a refusal)
    keys,     \* keys the machine made
    jkey,     \* the key the machine keeps for the token, 0 = none yet
    active,   \* a join runs (posted, waiting for its answer)
    jroot,    \* the root the join took, 0 = none
    result,   \* how the joins ended
    tries,    \* join runs
    lost      \* requests and answers the relay lost

vars == <<root, certs, revoked, other, replayed, reqs, ans, keys, jkey, active, jroot, result, tries, lost>>

TokCerts == {i \in DOMAIN certs : certs[i].tok}
Newest == certs[Len(certs)]

TypeOK ==
    /\ root \in 1..MaxRoot
    /\ \A i \in DOMAIN certs : certs[i].key \in 0..MaxKeys /\ certs[i].root \in 1..MaxRoot
    /\ revoked \in BOOLEAN /\ other \in BOOLEAN /\ replayed \in BOOLEAN
    /\ \A r \in reqs : r.key \in 0..MaxKeys /\ r.run \in 0..MaxTries
    /\ \A a \in ans : a.key \in 0..MaxKeys /\ a.cert \in 0..MaxCerts /\ a.run \in 0..MaxTries
    /\ keys \in 0..MaxKeys /\ jkey \in 0..MaxKeys /\ active \in BOOLEAN
    /\ jroot \in 0..Evil /\ result \in Results /\ tries \in 0..MaxTries /\ lost \in 0..MaxLost

Init ==
    /\ root = 1
    /\ certs = <<>>
    /\ revoked = FALSE /\ other = FALSE /\ replayed = FALSE
    /\ reqs = {} /\ ans = {}
    /\ keys = 0 /\ jkey = 0 /\ active = FALSE /\ jroot = 0
    /\ result = "none" /\ tries = 0 /\ lost = 0

\* The join's check of the root message (orgenrol.trust): the pinned root,
\* or a root the pinned recovery key certifies. Under pin-root-only (the
\* code before) the pinned root only; under any-root any root.
Trusts(g) ==
    \/ g = 1
    \/ Mutant # "pin-root-only" /\ g <= MaxRoot
    \/ Mutant = "any-root"

\* `nfltr org join` runs: the relay hands it root g (the owner's current,
\* or the attacker's); it refuses a root it does not trust, else posts the
\* request for the key it keeps for the token (a new one the first time,
\* and every time under new-key-per-join: the code before).
Start(g) ==
    /\ ~active /\ result = "none" /\ tries < MaxTries
    /\ g \in {root, Evil}
    /\ tries' = tries + 1
    /\ jroot' = g
    /\ IF ~Trusts(g)
       THEN /\ result' = "refused-root"
            /\ UNCHANGED <<root, certs, revoked, other, replayed, reqs, ans, keys, jkey, active, lost>>
       ELSE LET fresh == jkey = 0 \/ Mutant = "new-key-per-join"
                k == IF fresh THEN keys + 1 ELSE jkey IN
            /\ k <= MaxKeys
            /\ keys' = IF fresh THEN keys + 1 ELSE keys
            /\ jkey' = k
            /\ reqs' = reqs \cup {[key |-> k, run |-> tries + 1]}
            /\ active' = TRUE
            /\ UNCHANGED <<root, certs, revoked, other, replayed, ans, result, lost>>

\* The issuer reads a request and decides under its lock, as of now
\* (orgpki.Issuer.Enrol): a token not redeemed enrols the request's key; a
\* redeemed one is answered again, with a new certificate, only for the
\* key it enrolled, while the name is not revoked and its newest
\* certificate is still the token's (no renewal since); any other request
\* is refused. Mutants: burn-name refuses every request after the first
\* (the code before), reissue-any-key re-issues for any key,
\* reissue-revoked ignores the revoke, reissue-after-renewal re-issues a
\* key a renewal retired.
Reissues(k) ==
    /\ Mutant # "burn-name"
    /\ ~revoked \/ Mutant = "reissue-revoked"
    /\ Newest.tok \/ Mutant = "reissue-after-renewal"
    /\ (\E i \in TokCerts : certs[i].key = k) \/ Mutant = "reissue-any-key"
Issue(r) ==
    /\ r \in reqs
    /\ reqs' = reqs \ {r}
    /\ IF certs = <<>> \/ Reissues(r.key)
       THEN /\ Len(certs) < MaxCerts
            /\ certs' = Append(certs, [key |-> r.key, root |-> root, tok |-> TRUE, afterRevoke |-> revoked])
            /\ ans' = ans \cup {[key |-> r.key, cert |-> Len(certs) + 1, run |-> r.run]}
       ELSE /\ ans' = ans \cup {[key |-> r.key, cert |-> 0, run |-> r.run]}
            /\ UNCHANGED certs
    /\ UNCHANGED <<root, revoked, other, replayed, keys, jkey, active, jroot, result, tries, lost>>

\* The join reads the answer to its run's request, or to the first run's
\* (kept with the key: it carries the sealed A2A key): a certificate for
\* its key that chains to the root it took joins; a refusal, or a
\* certificate for another key, ends it refused.
Install(a) ==
    /\ active /\ a \in ans /\ a.run \in {1, tries}
    /\ IF a.cert # 0 /\ a.key = jkey
       THEN /\ certs[a.cert].root = jroot   \* else the chain check fails: not taken
            /\ result' = "joined"
       ELSE result' = "refused-token"
    /\ active' = FALSE
    /\ UNCHANGED <<root, certs, revoked, other, replayed, reqs, ans, keys, jkey, jroot, tries, lost>>

\* The join's wait ends (--wait) with no answer taken: the operator runs
\* it again (Start).
GiveUp ==
    /\ active
    /\ active' = FALSE
    /\ UNCHANGED <<root, certs, revoked, other, replayed, reqs, ans, keys, jkey, jroot, result, tries, lost>>

\* The relay loses a request or an answer (or keeps it past its TTL).
Lose ==
    /\ lost < MaxLost
    /\ lost' = lost + 1
    /\ \/ \E r \in reqs : reqs' = reqs \ {r} /\ ans' = ans
       \/ \E a \in ans : ans' = ans \ {a} /\ reqs' = reqs
    /\ UNCHANGED <<root, certs, revoked, other, replayed, keys, jkey, active, jroot, result, tries>>

\* The token leaked: whoever holds it posts a request for its own key.
Other ==
    /\ ~other
    /\ other' = TRUE
    /\ reqs' = reqs \cup {[key |-> OtherKey, run |-> 0]}
    /\ UNCHANGED <<root, certs, revoked, replayed, ans, keys, jkey, active, jroot, result, tries, lost>>

\* The machine renews (Enrol.tla Request, Issue, Install): a new key,
\* certified in the name's log, not under the token.
Renew ==
    /\ result = "joined" /\ ~revoked /\ Newest.tok
    /\ keys < MaxKeys /\ Len(certs) < MaxCerts
    /\ keys' = keys + 1
    /\ certs' = Append(certs, [key |-> keys + 1, root |-> root, tok |-> FALSE, afterRevoke |-> FALSE])
    /\ UNCHANGED <<root, revoked, other, replayed, reqs, ans, jkey, active, jroot, result, tries, lost>>

\* The machine's retired join key leaked (enrol.pv's web previous key):
\* the attacker posts a request for it with the token.
ReplayOld ==
    /\ ~replayed /\ \E i \in DOMAIN certs : ~certs[i].tok
    /\ replayed' = TRUE
    /\ reqs' = reqs \cup {[key |-> jkey, run |-> 0]}
    /\ UNCHANGED <<root, certs, revoked, other, ans, keys, jkey, active, jroot, result, tries, lost>>

\* The owner revokes the name.
Revoke ==
    /\ certs # <<>> /\ ~revoked
    /\ revoked' = TRUE
    /\ UNCHANGED <<root, certs, other, replayed, reqs, ans, keys, jkey, active, jroot, result, tries, lost>>

\* The owner rotates with the recovery key.
Rotate ==
    /\ root < MaxRoot
    /\ root' = root + 1
    /\ UNCHANGED <<certs, revoked, other, replayed, reqs, ans, keys, jkey, active, jroot, result, tries, lost>>

\* Under any-root the join takes the attacker's root, and the attacker
\* answers with a certificate of its own under it.
InstallForged ==
    /\ active /\ jroot = Evil
    /\ result' = "joined" /\ active' = FALSE
    /\ UNCHANGED <<root, certs, revoked, other, replayed, reqs, ans, keys, jkey, jroot, tries, lost>>

Next ==
    \/ \E g \in 1..Evil : Start(g)
    \/ \E r \in reqs : Issue(r)
    \/ \E a \in ans : Install(a)
    \/ GiveUp \/ Lose \/ Other \/ Renew \/ ReplayOld \/ Revoke \/ Rotate \/ InstallForged

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* Safety.

\* A token certifies one key only, however often it is answered.
OneKeyPerToken == \A i, j \in TokCerts : certs[i].key = certs[j].key

\* Nothing is issued under a token after the name's revoke.
NoIssueAfterRevoke == \A i \in DOMAIN certs : ~certs[i].afterRevoke

\* A key a renewal retired is never certified again by the token.
NoRetiredKeyRevived == \A i, j \in DOMAIN certs : j < i /\ certs[i].tok => certs[j].tok

\* A join is refused only for a cause: the token was redeemed by another
\* key or the name revoked; a root, only when it is not the owner's. A
\* lost or late answer never burns the name.
RefusedOnlyForCause ==
    /\ result = "refused-token" => revoked \/ other
    /\ result = "refused-root" => jroot = Evil

\* A machine joins only under a root the owner made.
JoinRootsAreOwners == result = "joined" => jroot # Evil

\* Witnesses (each must be violated: the states are reachable).
WitnessRetriedJoin == ~(result = "joined" /\ tries >= 2)
WitnessReissued == Cardinality(TokCerts) <= 1
WitnessJoinedAfterLoss == ~(result = "joined" /\ lost > 0)
WitnessJoinedAfterRotation == ~(result = "joined" /\ jroot > 1)
WitnessRefusedOther == ~(result = "refused-token" /\ other)
WitnessRefusedEvil == result # "refused-root"
=============================================================================
