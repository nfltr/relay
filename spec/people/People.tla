---------------------------- MODULE People ----------------------------
\* A people layer over an organisation (spec/people/README.md; nfltr
\* docs/decisions/people-layer-2026-11-25.md).
\*
\* A person signs in (OIDC) to join through an invite, owns machines, has
\* a role (owner, admin, member) and is offboarded in one act. Authority
\* stays with the organisation: the owner is the root holder (Touch ID),
\* an admin acts by a grant the root signed, and the issuer's log is the
\* roster. The IdP only authenticates a sign-in, the relay only carries;
\* who may forge what is spec/proverif/people.pv. Here: who may do what,
\* that no machine of a removed person keeps a credential, and that the
\* offboard reaches every credential within Bound.
\*
\* A machine holds three credentials: the organisation certificate
\* (verifiers learn its revoke from the CRL push, or refuse it once the
\* CRL they hold lapses: Enrol.tla's RevocationBound), the relay machine
\* credential (relay-server MachineAuth: revoke pushed to the relay) and
\* the nf1 addresses it serves (rotated by the machine's keeper, here the
\* org's service machine, or by the relay refusing the revoked machine).
\* Groups are machine attributes in the certificate (ONEGROUP mirrors them
\* to the relay): a revoked machine leaves every group.
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    People,     \* persons, the owner among them
    Owner,      \* the root holder
    Machines,
    MaxTime,    \* clock bound
    Bound,      \* the offboard's reach bound (the CRL's life, the push's bound)
    Mutant

NoTime == -1
NoOne == "none"
Roles == {"owner", "admin", "member"}

VARIABLES
    now,
    status,     \* status[p]: "none" (not a person yet), "active", "removed"
    role,       \* role[p]
    invite,     \* invite[p]: [st: none|open|used, role]
    code,       \* code[m]: the person a machine code for slot m was made for
    owner,      \* owner[m]: the person a machine belongs to
    cert,       \* cert[m]: "none", "live", "listed" (the issuer's CRL lists it)
    crl,        \* crl[m]: verifiers took a CRL listing m (or refused it, CRL lapsed)
    sess,       \* sess[m]: a verifier holds a session of m
    relay,      \* relay[m]: "none", "live", "filed" (revoke filed), "revoked"
    addr,       \* addr[m]: "none", "live", "filed", "rotated"
    revAt,      \* revAt[m]: when m was revoked
    audit       \* the issuer's log: [actor, arole, act, subj, srole, mach]

vars == <<now, status, role, invite, code, owner, cert, crl, sess, relay, addr, revAt, audit>>

Entry(a, ar, act, p, sr, m) == [actor |-> a, arole |-> ar, act |-> act, subj |-> p, srole |-> sr, mach |-> m]
Log(e) == audit' = audit \cup {e}

\* Who may do what: the owner anything; an admin invites and offboards
\* members only; joining and adding one's own machine need no role.
Allowed(ar, act, sr) ==
    \/ act \in {"join", "add"}
    \/ ar = "owner"
    \/ ar = "admin" /\ act \in {"invite", "offboard"} /\ sr = "member"

TypeOK ==
    /\ now \in 0..MaxTime
    /\ status \in [People -> {"none", "active", "removed"}]
    /\ role \in [People -> Roles]
    /\ code \in [Machines -> People \cup {NoOne}]
    /\ owner \in [Machines -> People \cup {NoOne}]
    /\ cert \in [Machines -> {"none", "live", "listed"}]
    /\ crl \in [Machines -> BOOLEAN]
    /\ sess \in [Machines -> BOOLEAN]
    /\ relay \in [Machines -> {"none", "live", "filed", "revoked"}]
    /\ addr \in [Machines -> {"none", "live", "filed", "rotated"}]

Init ==
    /\ now = 0
    /\ status = [p \in People |-> IF p = Owner THEN "active" ELSE "none"]
    /\ role = [p \in People |-> IF p = Owner THEN "owner" ELSE "member"]
    /\ invite = [p \in People |-> [st |-> "none", role |-> "member"]]
    /\ code = [m \in Machines |-> NoOne]
    /\ owner = [m \in Machines |-> NoOne]
    /\ cert = [m \in Machines |-> "none"]
    /\ crl = [m \in Machines |-> FALSE]
    /\ sess = [m \in Machines |-> FALSE]
    /\ relay = [m \in Machines |-> "none"]
    /\ addr = [m \in Machines |-> "none"]
    /\ revAt = [m \in Machines |-> NoTime]
    /\ audit = {}

Active(p) == status[p] = "active"
Free(m) == owner[m] = NoOne /\ code[m] = NoOne
Due(m) == revAt[m] # NoTime /\ now + 1 >= revAt[m] + Bound

\* An owner or admin invites p with a role (the invite carries a secret
\* the person's device proves at join: people.pv).
Invite(a, p, r) ==
    /\ Active(a) /\ a # p
    /\ status[p] = "none" /\ invite[p].st = "none"
    /\ r \in {"admin", "member"}
    /\ (Mutant = "admin-invites-admin" \/ Allowed(role[a], "invite", r))
    /\ invite' = [invite EXCEPT ![p] = [st |-> "open", role |-> r]]
    /\ Log(Entry(a, role[a], "invite", p, r, NoOne))
    /\ UNCHANGED <<now, status, role, code, owner, cert, crl, sess, relay, addr, revAt>>

\* p's device signs in and proves the invite: p becomes a person with the
\* invite's role and m its first machine.
Join(p, m) ==
    /\ \/ status[p] = "none" /\ (Mutant = "idp-alone-enrols" \/ invite[p].st = "open")
       \/ Mutant = "rejoin-old-invite" /\ status[p] = "removed" /\ invite[p].st = "used"
    /\ Free(m)
    /\ LET r == IF Mutant = "role-from-request" THEN "admin" ELSE invite[p].role
       IN /\ role' = [role EXCEPT ![p] = r]
          /\ Log(Entry(p, r, "join", p, r, m))
    /\ status' = [status EXCEPT ![p] = "active"]
    /\ invite' = [invite EXCEPT ![p].st = IF invite[p].st = "open" THEN "used" ELSE @]
    /\ owner' = [owner EXCEPT ![m] = p]
    /\ cert' = [cert EXCEPT ![m] = "live"]
    /\ relay' = [relay EXCEPT ![m] = "live"]
    /\ UNCHANGED <<now, code, crl, sess, addr, revAt>>

\* A person makes a machine code for a new machine of theirs ...
Mint(p, m) ==
    /\ Active(p) /\ Free(m)
    /\ code' = [code EXCEPT ![m] = p]
    /\ UNCHANGED <<now, status, role, invite, owner, cert, crl, sess, relay, addr, revAt, audit>>

\* ... and the machine redeems it: the issuer decides by the person's
\* status when it answers, not when the code was made.
Redeem(m) ==
    /\ code[m] # NoOne /\ owner[m] = NoOne
    /\ (Mutant = "code-outlives-offboard" \/ Active(code[m]))
    /\ owner' = [owner EXCEPT ![m] = code[m]]
    /\ cert' = [cert EXCEPT ![m] = "live"]
    /\ relay' = [relay EXCEPT ![m] = "live"]
    /\ Log(Entry(code[m], role[code[m]], "add", code[m], role[code[m]], m))
    /\ UNCHANGED <<now, status, role, invite, code, crl, sess, addr, revAt>>

\* A machine serves an nf1 address.
Serve(m) ==
    /\ cert[m] = "live" /\ addr[m] = "none"
    /\ addr' = [addr EXCEPT ![m] = "live"]
    /\ UNCHANGED <<now, status, role, invite, code, owner, cert, crl, sess, relay, revAt, audit>>

\* A verifier admits a session of m: its certificate is live, or listed
\* in a CRL that has not reached the verifier yet (the window).
Open(m) ==
    /\ ~sess[m]
    /\ cert[m] = "live" \/ (cert[m] = "listed" /\ ~crl[m])
    /\ sess' = [sess EXCEPT ![m] = TRUE]
    /\ UNCHANGED <<now, status, role, invite, code, owner, cert, crl, relay, addr, revAt, audit>>

\* The owner (the root, Touch ID) changes an active person's role.
ChangeRole(a, p, r) ==
    /\ Active(a) /\ Active(p) /\ p # Owner /\ a # p
    /\ r \in {"admin", "member"} /\ r # role[p]
    /\ (Mutant = "admin-changes-role" \/ Allowed(role[a], "role", r))
    /\ role' = [role EXCEPT ![p] = r]
    /\ IF Mutant = "role-unlogged" THEN UNCHANGED audit ELSE Log(Entry(a, role[a], "role", p, r, NoOne))
    /\ UNCHANGED <<now, status, invite, code, owner, cert, crl, sess, relay, addr, revAt>>

\* Offboard: one act. The person is removed, every machine of theirs is
\* listed in the CRL, its relay credential's revoke and its addresses'
\* rotation are filed. The owner leaves only by moving the root (OrgMove).
Offboard(a, p) ==
    /\ Active(a) /\ Active(p) /\ p # Owner /\ a # p
    /\ (Mutant = "admin-offboards-admin" \/ Allowed(role[a], "offboard", role[p]))
    /\ status' = [status EXCEPT ![p] = "removed"]
    /\ LET all == {m \in Machines : owner[m] = p}
       IN \E ms \in (IF Mutant = "offboard-misses-machine" /\ all # {} THEN {all \ {x} : x \in all} ELSE {all}) :
          /\ cert' = [m \in Machines |-> IF m \in ms /\ cert[m] = "live" THEN "listed" ELSE cert[m]]
          /\ relay' = [m \in Machines |-> IF m \in ms /\ relay[m] = "live" /\ Mutant # "relay-not-filed" THEN "filed" ELSE relay[m]]
          /\ addr' = [m \in Machines |-> IF m \in ms /\ addr[m] = "live" THEN "filed" ELSE addr[m]]
          /\ revAt' = [m \in Machines |-> IF m \in ms THEN now ELSE revAt[m]]
    /\ IF Mutant = "offboard-unlogged" THEN UNCHANGED audit ELSE Log(Entry(a, role[a], "offboard", p, role[p], NoOne))
    /\ UNCHANGED <<now, role, invite, code, owner, crl, sess>>

\* The CRL push reaches the verifiers: they end m's sessions.
Reach(m) ==
    /\ cert[m] = "listed" /\ ~crl[m]
    /\ crl' = [crl EXCEPT ![m] = TRUE]
    /\ sess' = [sess EXCEPT ![m] = FALSE]
    /\ UNCHANGED <<now, status, role, invite, code, owner, cert, relay, addr, revAt, audit>>

RelayRevoke(m) ==
    /\ relay[m] = "filed"
    /\ relay' = [relay EXCEPT ![m] = "revoked"]
    /\ UNCHANGED <<now, status, role, invite, code, owner, cert, crl, sess, addr, revAt, audit>>

Rotate(m) ==
    /\ addr[m] = "filed"
    /\ addr' = [addr EXCEPT ![m] = "rotated"]
    /\ UNCHANGED <<now, status, role, invite, code, owner, cert, crl, sess, relay, revAt, audit>>

\* Time passes. A verifier whose CRL lapsed refuses (fail closed): by
\* revAt + Bound every verifier has taken the listing or refuses m. The
\* relay's revoke push and the address rotation are honest within Bound
\* (environment, README); time does not pass them.
Tick ==
    /\ now < MaxTime
    /\ \A m \in Machines : Due(m) => relay[m] # "filed" /\ addr[m] # "filed"
    /\ now' = now + 1
    /\ IF Mutant = "no-fail-closed" THEN UNCHANGED <<crl, sess>>
       ELSE /\ crl' = [m \in Machines |-> crl[m] \/ (cert[m] = "listed" /\ Due(m))]
            /\ sess' = [m \in Machines |-> sess[m] /\ ~(cert[m] = "listed" /\ Due(m))]
    /\ UNCHANGED <<status, role, invite, code, owner, cert, relay, addr, revAt, audit>>

Next ==
    \/ Tick
    \/ \E a, p \in People, r \in {"admin", "member"} : Invite(a, p, r) \/ ChangeRole(a, p, r)
    \/ \E a, p \in People : Offboard(a, p)
    \/ \E p \in People, m \in Machines : Join(p, m) \/ Mint(p, m)
    \/ \E m \in Machines : Redeem(m) \/ Serve(m) \/ Open(m) \/ Reach(m) \/ RelayRevoke(m) \/ Rotate(m)

Spec == Init /\ [][Next]_vars

\* ---- invariants ----

\* Every act in the log was one its actor's role allowed.
AuthorizedActs == \A e \in audit : Allowed(e.arole, e.act, e.srole)

\* An admin is one the owner made: by an invite or a role change the
\* owner logged.
AdminsByOwner ==
    \A p \in People : (status[p] # "none" /\ role[p] = "admin") =>
        \E e \in audit : e.subj = p /\ e.srole = "admin" /\ e.act \in {"invite", "role"} /\ e.arole = "owner"

\* No person without an invite: the IdP's sign-in alone enrols no one.
JoinNeedsInvite == \A p \in People \ {Owner} : status[p] # "none" => invite[p].st = "used"

\* No orphan: a machine of a removed person holds no live credential.
NoOrphan ==
    \A m \in Machines : (owner[m] # NoOne /\ status[owner[m]] = "removed") =>
        cert[m] # "live" /\ relay[m] # "live" /\ addr[m] # "live"

\* Bound after an offboard, nothing of the machine is left: no session,
\* the relay credential revoked, the addresses rotated.
ReachBound ==
    \A m \in Machines : (revAt[m] # NoTime /\ now >= revAt[m] + Bound) =>
        ~sess[m] /\ relay[m] \in {"none", "revoked"} /\ addr[m] \in {"none", "rotated"}

\* The log names every person's join, machine and offboard.
AuditComplete ==
    /\ \A p \in People \ {Owner} : status[p] # "none" => \E e \in audit : e.act = "join" /\ e.subj = p
    /\ \A p \in People : status[p] = "removed" => \E e \in audit : e.act = "offboard" /\ e.subj = p
    /\ \A m \in Machines : owner[m] # NoOne => \E e \in audit : e.mach = m /\ e.subj = owner[m]
    /\ \A p \in People : (status[p] # "none" /\ role[p] # "member" /\ p # Owner) =>
        \E e \in audit : e.subj = p /\ e.srole = role[p] /\ e.act \in {"invite", "role"}

OwnerStays == status[Owner] = "active"

\* A removed person stays removed (a new invite is a new person here).
RemovedStaysOut == [][\A p \in People : status[p] = "removed" => status'[p] = "removed"]_vars

\* ---- witnesses (each must be violated: the state is reachable) ----
WitnessJoined == ~\E p \in People \ {Owner} : Active(p)
WitnessAdminActs == ~\E e \in audit : e.arole = "admin" /\ e.act \in {"invite", "offboard"}
WitnessSecondMachine == ~\E p \in People \ {Owner} : Cardinality({m \in Machines : owner[m] = p}) >= 2
WitnessRoleChanged == ~\E e \in audit : e.act = "role"
\* the residual the bound states: a removed person's session still open
WitnessWindow == ~\E m \in Machines : owner[m] # NoOne /\ status[owner[m]] = "removed" /\ sess[m]
WitnessOffboardReached == ~\E m \in Machines : revAt[m] # NoTime /\ crl[m] /\ relay[m] = "revoked" /\ addr[m] = "rotated"

Sym == Permutations(Machines) \cup Permutations(People \ {Owner})
=============================================================================
