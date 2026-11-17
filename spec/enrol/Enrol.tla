---------------------------- MODULE Enrol ----------------------------
\* The lifecycle of organisation certificates (spec/enrol/README.md):
\* renewal,
\* revocation through a signed CRL the relay carries (and may replay or
\* withhold), and root rotation after the root's primary key is stolen.
\* Enrolment itself (tokens, names, chains) is spec/proverif/enrol.pv.
\*
\* A verifier (a client or a service) admits a session under a
\* certificate while: the certificate has not expired, it chains to the
\* root the verifier trusts, the verifier holds a CRL whose NextUpdate has
\* not passed, and that CRL does not list the certificate's serial (x509:
\* the issuer lists every unexpired serial of a revoked name). It keeps a timer to the earlier of the certificate's NotAfter
\* and the CRL's NextUpdate, and re-checks its sessions on each CRL and
\* rotation it takes. Time is discrete (Tick), bounded by MaxTime.
\*
\* A renewal is a round trip through relay mailboxes: the
\* machine makes a new key and posts a request (Request), the issuer
\* answers it under its lock when it reads it (Issue), and the machine
\* installs the answer for the key it made last (Install). The relay
\* carries requests and answers and may lose them (Lose) or hand back an
\* old answer; a machine whose request or answer is gone asks again with a
\* new key.
\*
\* A rebind (nfltr docs/decisions/org-rebind-2026-11-17.md; RFC 7030
\* simplereenroll) moves an enrolled name to a new relay machine id: the
\* issuer certifies the new machine (its join is Join.tla's, the token's
\* authority enrol.pv's) and, in the same log entry, retires every
\* earlier serial of the name, listed in the CRL it signs then. The old
\* machine's disk (its certificate and key) is the attacker's from then:
\* any of its certificates can be presented (Admit) and its renewal
\* requests still sit in the relay's mailbox (Issue must refuse them).
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    NM,           \* machines 1..NM
    NV,           \* verifiers 1..NV
    MaxTime,
    CertLife,     \* a certificate's NotAfter - NotBefore
    RenewBefore,  \* a machine renews this long before NotAfter
    CrlLife,      \* a CRL's NextUpdate - ThisUpdate: the bound on a revocation the relay withholds
    MaxCrls,      \* CRLs the issuer publishes (state bound)
    MaxRoot,      \* the owner's root generations 1..MaxRoot
    MaxForged,    \* certificates the attacker mints under a stolen root
    MaxKeys,      \* keys a machine makes without a loss (renewal requests + 1: state bound)
    MaxLost,      \* requests or answers the relay loses
    MaxRebinds,   \* 0 or 1: whether a machine is rebound (Rebind.cfg; state bound)
    Mutant

Machines == 1..NM
Verifiers == 1..NV
EvilRoot == MaxRoot + 1       \* a root the attacker made (only under a mutant)

VARIABLES
    now,
    certs,      \* every certificate issued: <<[m, iss, exp, root, forged, key]>>, index = serial
    cur,        \* cur[m]: the serial the machine itself holds
    revokedAt,  \* revokedAt[m]: when the owner revoked m, -1 if not
    crls,       \* every CRL published: <<[this, next, rev]>>, index = CRL number
    seen,       \* seen[v]: the CRL number v holds (the newest it took)
    maxSeen,    \* history: the highest CRL number v ever took
    vroot,      \* vroot[v]: the root generation v trusts
    root,       \* the owner's current root generation
    stolen,     \* root generations whose primary key the attacker holds
    evil,       \* the attacker published a rotation of its own (mutant only)
    sess,       \* sessions held: [v, c]
    keys,       \* keys[m]: the keys m made; its newest is keys[m]
    want,       \* want[m]: the key m waits an answer for, 0 = none
    reqs,       \* renewal requests the relay carries: [m, from, key, ok]
    ans,        \* answers the relay carries (serials); it may keep old ones
    lost,       \* requests and answers the relay lost
    rebound,    \* rebound[m]: Len(certs) at m's rebind: serials <= it are retired; 0 = none
    rebindCrl   \* rebindCrl[m]: the CRL the rebind signed, 0 = none

vars == <<now, certs, cur, revokedAt, crls, seen, maxSeen, vroot, root, stolen, evil, sess, keys, want, reqs, ans, lost, rebound, rebindCrl>>
rt == <<keys, want, reqs, ans, lost, rebound, rebindCrl>>

Last == crls[Len(crls)]
SerialsOf(m) == {i \in DOMAIN certs : certs[i].m = m /\ ~certs[i].forged}
Unrevoked(m) == revokedAt[m] = -1
\* A serial a rebind retired (the old machine id's), and m's others.
Retired(i) == ~certs[i].forged /\ i <= rebound[certs[i].m]
Current(m) == {i \in SerialsOf(m) : ~Retired(i)}
\* The machines whose revocation v has learned: a current serial of
\* theirs is in the newest CRL v took (a rebind lists only retired ones).
RevokedSeen(v) == {m \in Machines : Current(m) \cap crls[maxSeen[v]].rev # {}}
Forged == Cardinality({i \in DOMAIN certs : certs[i].forged})

\* The verifier's check (enrol.pv's Client and Service, in state).
RootOK(v, i) ==
    IF Mutant = "keep-old-root" THEN certs[i].root <= vroot[v] ELSE certs[i].root = vroot[v]
Fresh(v, t) == Mutant = "fail-open" \/ crls[seen[v]].next > t
NotExpired(i, t) == certs[i].exp > t
\* x509: the CRL lists serials; the verifier looks up the one presented.
Listed(v, i) == Mutant # "no-crl-check" /\ i \in crls[seen[v]].rev
Valid(v, i, t) ==
    /\ Mutant = "no-expiry-check" \/ NotExpired(i, t)
    /\ RootOK(v, i)
    /\ Fresh(v, t)
    /\ ~Listed(v, i)
\* A held session survives a tick or a CRL only while it still checks.
Keeps(s, t) ==
    /\ Mutant \in {"no-expiry-check", "no-expiry-timer"} \/ NotExpired(s.c, t)
    /\ Fresh(s.v, t)

TypeOK ==
    /\ now \in 0..MaxTime
    /\ \A i \in DOMAIN certs : certs[i].m \in Machines /\ certs[i].root \in 1..EvilRoot
    /\ cur \in [Machines -> DOMAIN certs]
    /\ revokedAt \in [Machines -> -1..MaxTime]
    /\ seen \in [Verifiers -> DOMAIN crls] /\ maxSeen \in [Verifiers -> DOMAIN crls]
    /\ vroot \in [Verifiers -> 1..EvilRoot]
    /\ root \in 1..MaxRoot
    /\ stolen \subseteq 1..EvilRoot
    /\ evil \in BOOLEAN
    /\ \A s \in sess : s.v \in Verifiers /\ s.c \in DOMAIN certs
    /\ keys \in [Machines -> 1..MaxKeys + MaxLost + 1] /\ want \in [Machines -> 0..MaxKeys + MaxLost + 1]
    /\ \A r \in reqs : r.m \in Machines /\ r.from \in DOMAIN certs /\ r.key \in 1..MaxKeys + MaxLost + 1
    /\ ans \subseteq DOMAIN certs /\ lost \in 0..MaxLost
    /\ rebound \in [Machines -> 0..Len(certs)] /\ rebindCrl \in [Machines -> 0..Len(crls)]

Init ==
    /\ now = 0
    /\ certs = [i \in Machines |-> [m |-> i, iss |-> 0, exp |-> CertLife, root |-> 1, forged |-> FALSE, key |-> 1, from |-> 0]]
    /\ cur = [m \in Machines |-> m]
    /\ revokedAt = [m \in Machines |-> -1]
    /\ crls = <<[this |-> 0, next |-> CrlLife, rev |-> {}]>>
    /\ seen = [v \in Verifiers |-> 1]
    /\ maxSeen = [v \in Verifiers |-> 1]
    /\ vroot = [v \in Verifiers |-> 1]
    /\ root = 1
    /\ stolen = {}
    /\ evil = FALSE
    /\ sess = {}
    /\ keys = [m \in Machines |-> 1]
    /\ want = [m \in Machines |-> 0]
    /\ reqs = {} /\ ans = {} /\ lost = 0
    /\ rebound = [m \in Machines |-> 0] /\ rebindCrl = [m \in Machines |-> 0]

\* Time passes; each verifier's timer ends sessions whose certificate
\* expired or whose CRL lapsed (fail closed).
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ sess' = {s \in sess : Keeps(s, now + 1)}
    /\ UNCHANGED <<certs, cur, revokedAt, crls, seen, maxSeen, vroot, root, stolen, evil>> /\ UNCHANGED rt

\* A peer presents certificate i (honest, a stolen machine's, or forged).
Admit(v, i) ==
    /\ [v |-> v, c |-> i] \notin sess
    /\ Valid(v, i, now)
    /\ sess' = sess \cup {[v |-> v, c |-> i]}
    /\ UNCHANGED <<now, certs, cur, revokedAt, crls, seen, maxSeen, vroot, root, stolen, evil>> /\ UNCHANGED rt

\* A machine renews with its current certificate, before NotAfter, in the
\* window or because the root rotated: a new key and a request for it,
\* posted to the issuer's mailbox. It asks again (a new key) only when
\* its request and its answer are both gone (the machine's timeout: an
\* untimed model cannot tell slow from lost, and asking early only adds a
\* request); under no-retry it never asks again while it waits.
Due(m, i) ==
    \/ certs[i].exp - now <= RenewBefore
    \/ Mutant # "no-reissue-on-rotation" /\ certs[i].root < root
\* m's answers once it installs one or asks again: dead, since no honest
\* machine installs an answer for another key than its newest (the relay
\* keeps them; dropping them only prunes states). Kept under
\* install-stale-answer, which installs them.
Live(a, m) == IF Mutant = "install-stale-answer" THEN a ELSE {i \in a : certs[i].m # m}
Pending(m) ==
    \/ \E r \in reqs : r.m = m /\ r.key = want[m]
    \/ \E i \in ans : certs[i].m = m /\ certs[i].key = want[m]
\* (A loss grants one key more, and so does a rebind (its key): the bound
\* never stops a retry.)
Request(m) ==
    /\ keys[m] < MaxKeys + lost + IF rebound[m] > 0 THEN 1 ELSE 0
    /\ IF Mutant = "no-retry" THEN want[m] = 0 ELSE want[m] = 0 \/ ~Pending(m)
    /\ NotExpired(cur[m], now)
    /\ Due(m, cur[m])
    /\ keys' = [keys EXCEPT ![m] = keys[m] + 1]
    /\ want' = [want EXCEPT ![m] = keys[m] + 1]
    /\ reqs' = reqs \cup {[m |-> m, from |-> cur[m], key |-> keys[m] + 1,
                           ok |-> Mutant # "check-at-request" \/ Unrevoked(m)]}
    /\ ans' = Live(ans, m)
    /\ UNCHANGED <<now, certs, cur, revokedAt, crls, seen, maxSeen, vroot, root, stolen, evil, sess, lost, rebound, rebindCrl>>

\* The issuer reads a request and decides under its lock, as of now: it
\* refuses a revoked name and an expired certificate, and renews only a
\* serial its own log holds (requests carry honest serials; the attacker's
\* forged one is IssueForged). Under check-at-request it decides by the
\* state when the request was posted (a revoke while the request sat in
\* the mailbox is missed). It takes the request (acks it) and posts the
\* answer.
Issue(r) ==
    /\ r \in reqs
    /\ IF Mutant = "check-at-request" THEN r.ok
       ELSE Mutant = "renew-revoked" \/ Unrevoked(r.m)
    /\ NotExpired(r.from, now)
    /\ Mutant = "renew-rebound" \/ ~Retired(r.from)
    /\ certs' = Append(certs, [m |-> r.m, iss |-> now, exp |-> now + CertLife, root |-> root, forged |-> FALSE, key |-> r.key, from |-> r.from])
    /\ reqs' = reqs \ {r}
    /\ ans' = ans \cup {Len(certs) + 1}
    /\ UNCHANGED <<now, cur, revokedAt, crls, seen, maxSeen, vroot, root, stolen, evil, sess, keys, want, lost, rebound, rebindCrl>>

\* Under renew-forged the issuer also renews a forged certificate the
\* attacker presents, into the current root.
IssueForged(i) ==
    /\ Mutant = "renew-forged"
    /\ certs[i].forged /\ Forged <= MaxForged
    /\ Unrevoked(certs[i].m) /\ NotExpired(i, now) /\ Due(certs[i].m, i)
    /\ certs' = Append(certs, [certs[i] EXCEPT !.iss = now, !.exp = now + CertLife, !.root = root])
    /\ UNCHANGED <<now, cur, revokedAt, crls, seen, maxSeen, vroot, root, stolen, evil, sess>> /\ UNCHANGED rt

\* The machine installs an answer the relay hands it: only one for the key
\* it made last (under install-stale-answer, any of its answers).
Install(m, i) ==
    /\ i \in ans /\ certs[i].m = m /\ want[m] # 0
    /\ Mutant = "install-stale-answer" \/ certs[i].key = want[m]
    /\ cur' = [cur EXCEPT ![m] = i]
    /\ want' = [want EXCEPT ![m] = 0]
    /\ ans' = Live(ans, m)
    /\ UNCHANGED <<now, certs, revokedAt, crls, seen, maxSeen, vroot, root, stolen, evil, sess, keys, reqs, lost, rebound, rebindCrl>>

\* The relay loses a request or an answer.
Lose ==
    /\ lost < MaxLost
    /\ lost' = lost + 1
    /\ \/ \E r \in reqs : reqs' = reqs \ {r} /\ ans' = ans
       \/ \E i \in ans : ans' = ans \ {i} /\ reqs' = reqs
    /\ UNCHANGED <<now, certs, cur, revokedAt, crls, seen, maxSeen, vroot, root, stolen, evil, sess, keys, want, rebound, rebindCrl>>

\* The owner revokes m; the issuer signs a CRL listing all of m's serials
\* at once and the issuer pushes it (Fetch).
Revoke(m) ==
    /\ Unrevoked(m)
    /\ revokedAt' = [revokedAt EXCEPT ![m] = now]
    /\ crls' = Append(crls, [this |-> now, next |-> now + CrlLife,
                             rev |-> Last.rev \cup IF Mutant = "revoke-current-only" THEN {cur[m]} ELSE SerialsOf(m)])
    /\ UNCHANGED <<now, certs, cur, seen, maxSeen, vroot, root, stolen, evil, sess>> /\ UNCHANGED rt

\* The owner's rebind token redeemed by m's new machine (its new relay
\* machine id): one log entry certifies the new machine for a new key and
\* retires every earlier serial of m; the CRL then signed lists them (under
\* rebind-keeps-serials it does not). The new machine holds the new
\* certificate; whatever the old one waited for is dead (its requests stay
\* in the relay's mailbox). One rebind per machine (state bound).
Rebind(m) ==
    /\ MaxRebinds > 0 /\ Unrevoked(m) /\ rebound[m] = 0
    /\ certs' = Append(certs, [m |-> m, iss |-> now, exp |-> now + CertLife, root |-> root, forged |-> FALSE, key |-> keys[m] + 1, from |-> 0])
    /\ rebound' = [rebound EXCEPT ![m] = Len(certs)]
    /\ crls' = Append(crls, [this |-> now, next |-> now + CrlLife,
                             rev |-> Last.rev \cup IF Mutant = "rebind-keeps-serials" THEN {} ELSE SerialsOf(m)])
    /\ rebindCrl' = [rebindCrl EXCEPT ![m] = Len(crls) + 1]
    /\ cur' = [cur EXCEPT ![m] = Len(certs) + 1]
    /\ keys' = [keys EXCEPT ![m] = keys[m] + 1]
    /\ want' = [want EXCEPT ![m] = 0]
    /\ ans' = Live(ans, m)
    /\ UNCHANGED <<now, revokedAt, seen, maxSeen, vroot, root, stolen, evil, sess, reqs, lost>>

\* The issuer re-signs the CRL before its NextUpdate.
Republish ==
    /\ Len(crls) < MaxCrls
    /\ Last.next - now <= 1
    /\ crls' = Append(crls, [this |-> now, next |-> now + CrlLife, rev |-> Last.rev])
    /\ UNCHANGED <<now, certs, cur, revokedAt, seen, maxSeen, vroot, root, stolen, evil, sess>> /\ UNCHANGED rt

\* v takes CRL n: only a newer one; it re-checks its sessions.
Take(v, n) ==
    /\ IF Mutant = "accept-older-crl" THEN n # seen[v] ELSE n > seen[v]
    /\ seen' = [seen EXCEPT ![v] = n]
    /\ maxSeen' = [maxSeen EXCEPT ![v] = IF n > maxSeen[v] THEN n ELSE maxSeen[v]]
    /\ sess' = IF Mutant = "no-cut-on-update" THEN sess
               ELSE {s \in sess : s.v # v \/ (Keeps(s, now) /\ s.c \notin crls[n].rev)}
    /\ UNCHANGED <<now, certs, cur, revokedAt, crls, vroot, root, stolen, evil>> /\ UNCHANGED rt

\* The relay replays an older CRL, when it likes.
Replay(v, n) ==
    /\ n < Len(crls)
    /\ Take(v, n)

\* v takes the newest CRL: the issuer's push, or v's own backstop read
\* before its CRL's NextUpdate. The backstop makes it fair (LiveSpec):
\* the network eventually answers. Under push-only there is no backstop,
\* so a lost push is never made good.
Fetch(v) == Take(v, Len(crls))

\* The attacker takes the current root's primary key.
Steal ==
    /\ root \notin stolen
    /\ stolen' = stolen \cup {root}
    /\ UNCHANGED <<now, certs, cur, revokedAt, crls, seen, maxSeen, vroot, root, evil, sess>> /\ UNCHANGED rt

\* ... and mints a certificate under it, for any name.
Forge(m, g) ==
    /\ g \in stolen
    /\ Forged < MaxForged
    /\ certs' = Append(certs, [m |-> m, iss |-> now, exp |-> now + CertLife, root |-> g, forged |-> TRUE, from |-> 0])
    /\ UNCHANGED <<now, cur, revokedAt, crls, seen, maxSeen, vroot, root, stolen, evil, sess>> /\ UNCHANGED rt

\* The owner rotates with the recovery key; the new root certifies a new
\* issuer, and machines re-enrol by renewal (Request, Issue, Install).
Rotate ==
    /\ root \in stolen
    /\ root < MaxRoot
    /\ root' = root + 1
    /\ UNCHANGED <<now, certs, cur, revokedAt, crls, seen, maxSeen, vroot, stolen, evil, sess>> /\ UNCHANGED rt

\* Under rotate-by-primary a stolen primary signs a rotation of its own.
EvilRotate ==
    /\ Mutant = "rotate-by-primary"
    /\ stolen # {} /\ ~evil
    /\ evil' = TRUE
    /\ stolen' = stolen \cup {EvilRoot}
    /\ UNCHANGED <<now, certs, cur, revokedAt, crls, seen, maxSeen, vroot, root, sess>> /\ UNCHANGED rt

\* v takes a rotation statement (the relay carries it; it is signed, so v
\* takes only the owner's, or the attacker's under the mutant) and ends
\* sessions under any other root.
TakeRoot(v) ==
    /\ \/ vroot[v] < root /\ vroot' = [vroot EXCEPT ![v] = root]
       \/ evil /\ vroot[v] # EvilRoot /\ vroot' = [vroot EXCEPT ![v] = EvilRoot]
    /\ sess' = IF Mutant = "keep-old-root" THEN sess
               ELSE {s \in sess : s.v # v \/ certs[s.c].root = vroot'[v]}
    /\ UNCHANGED <<now, certs, cur, revokedAt, crls, seen, maxSeen, root, stolen, evil>> /\ UNCHANGED rt

Next ==
    \/ Tick
    \/ \E v \in Verifiers, i \in DOMAIN certs : Admit(v, i)
    \/ \E m \in Machines : Request(m) \/ Revoke(m) \/ Rebind(m)
    \/ \E r \in reqs : Issue(r)
       \* (one disjunct for coverage: IssueForged is mutant-only)
       \/ \E i \in DOMAIN certs : IssueForged(i)
    \/ \E m \in Machines, i \in ans : Install(m, i)
    \/ Lose
    \/ Republish
    \/ \E v \in Verifiers, n \in DOMAIN crls : Replay(v, n)
    \/ \E v \in Verifiers : Fetch(v) \/ TakeRoot(v)
    \/ Steal \/ Rotate \/ EvilRotate
    \/ \E m \in Machines, g \in 1..EvilRoot : Forge(m, g)

Spec == Init /\ [][Next]_vars

\* Fair: the backstop fetch (none under push-only), taking a rotation,
\* and renewal: the machine asks, the issuer answers what reaches it, the
\* machine installs what reaches it (the relay loses at most MaxLost).
LiveSpec == Spec
    /\ \A v \in Verifiers : (Mutant = "push-only" \/ WF_vars(Fetch(v))) /\ WF_vars(TakeRoot(v))
    /\ \A m \in Machines : WF_vars(Request(m))
                          /\ WF_vars(\E r \in reqs : r.m = m /\ Issue(r))
                          /\ WF_vars(\E i \in ans : Install(m, i))

----------------------------------------------------------------------------
\* Safety.

\* CrlLife after a revoke, no verifier holds a session of the revoked
\* machine, whatever the relay delivered (it can replay or withhold CRLs).
RevocationBound ==
    \A s \in sess : LET m == certs[s.c].m IN
        certs[s.c].forged \/ Unrevoked(m) \/ now < revokedAt[m] + CrlLife

\* Once v has taken a CRL naming m, v holds no session of m again (any of
\* its serials, renewed ones included).
RevokedMachineRefused ==
    \A s \in sess : certs[s.c].forged \/ certs[s.c].m \notin RevokedSeen(s.v)

\* CrlLife after a rebind, no verifier holds a session of a serial it
\* retired (the old machine's disk), whatever the relay delivered.
RebindBound ==
    \A s \in sess : ~Retired(s.c) \/ now < crls[rebindCrl[certs[s.c].m]].this + CrlLife

\* Once v has taken the rebind's CRL (or a later one), v holds no session
\* of a retired serial.
RetiredRefused ==
    \A s \in sess : ~Retired(s.c) \/ maxSeen[s.v] < rebindCrl[certs[s.c].m]

\* The issuer renews no serial a rebind retired: every certificate of m
\* issued after its rebind is the rebind's or renews a current one.
NoRenewOfRetired ==
    \A i \in DOMAIN certs : certs[i].forged \/ certs[i].from = 0 \/ Retired(i) \/ ~Retired(certs[i].from)

\* No session outlives its certificate.
NoExpiredSession == \A s \in sess : NotExpired(s.c, now)

\* The issuer never certifies a machine after its revoke.
NoRenewAfterRevoke ==
    \* (a renewal at the revoke's own instant is ordered before it by the
    \* issuer's lock; the CRL then lists it)
    \A i \in DOMAIN certs : certs[i].forged \/ Unrevoked(certs[i].m) \/ certs[i].iss <= revokedAt[certs[i].m]

\* A forged certificate exists only under a stolen root: the issuer
\* renews only serials its own log holds, never one presented under an
\* old root it did not issue.
ForgedOnlyUnderStolenRoot == \A i \in DOMAIN certs : ~certs[i].forged \/ certs[i].root \in stolen

\* Every session is under the root its verifier trusts (a rotation ends
\* the stolen root's sessions, forged ones included).
SessionsOnTrustedRoot == \A s \in sess : certs[s.c].root = vroot[s.v]

\* A verifier trusts only roots the owner made (with the recovery key).
RootsAreOwners == \A v \in Verifiers : vroot[v] <= MaxRoot

\* A machine that waits for no answer holds the certificate of the key it
\* made last: it never installs an answer for a key it gave up (the
\* relay's old answer).
MachineHoldsItsKey == \A m \in Machines : want[m] = 0 => certs[cur[m]].key = keys[m]

\* Liveness (LiveSpec): every revoke reaches every verifier, and every
\* machine still enrolled moves to the new root.
TakesEffect == \A m \in Machines, v \in Verifiers : (~Unrevoked(m)) ~> (m \in RevokedSeen(v))
MachinesFollowRotation ==
    \A m \in Machines, g \in 2..MaxRoot :
        (root = g) ~> (~Unrevoked(m) \/ certs[cur[m]].root >= g \/ ~NotExpired(cur[m], now))

\* Witnesses (each must be violated: the states are reachable).
WitnessRenewed == \A m \in Machines : certs[cur[m]].iss = 0
WitnessRevokeSeen == \A v \in Verifiers : RevokedSeen(v) = {}
WitnessFailClosed == \A v \in Verifiers : crls[seen[v]].next > now
WitnessForgedSession == \A s \in sess : ~certs[s.c].forged
WitnessRotated == \A v \in Verifiers : vroot[v] = 1
WitnessSessionAfterRotation == \A s \in sess : certs[s.c].root = 1
WitnessRebound == \A m \in Machines : rebound[m] = 0
WitnessSessionAfterRebind == \A s \in sess : rebound[certs[s.c].m] = 0 \/ Retired(s.c)
WitnessRetiredHeld == \A s \in sess : ~Retired(s.c)
WitnessRetried == \A m \in Machines : keys[m] <= 2 \/ lost = 0
=============================================================================
