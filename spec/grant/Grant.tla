---------------------------- MODULE Grant ----------------------------
\* Time-limited, approved access to one service (spec/grant/README.md;
\* nfltr docs/decisions/service-access-2026-11-25.md). Built in lane SA4
\* (org/orgpki grant.go, client/orgid grant.go; README "Code map").
\*
\* A principal (a person's device or a machine, by its organisation
\* certificate) asks for a service for a duration; an approver signs that
\* request (Touch ID on the approver's device); the organisation's issuer
\* checks the approver's authority over the service and signs a grant
\* [principal, service, until] once per request. The client holds the
\* grant and presents it inside the end-to-end TLS session (an SSH
\* certificate's validity window, a short-lived X.509 attribute); the
\* serving agent admits the session only for the grant's principal and
\* service, before its until, while the grant is not on the issuer's
\* revocation list, and while the list it holds is fresh (younger than
\* CrlLife: RFC 5280 nextUpdate). The agent's own timer ends the session at
\* until; a newer list naming the grant ends it on arrival; a list grown
\* stale ends every grant session (fail closed for elevated access only).
\*
\* The attacker owns the relay: it replays any approval it carried, any
\* number of times, withholds or delays every revocation list, and offers
\* the agent any principal's grant. Signatures are not modelled here (who
\* can forge or widen what is spec/proverif/svc_access.pv); the approval
\* signs the request, so its fields are the request's. The person's and
\* machine's certificates (revoke, offboard) are spec/enrol and
\* spec/people; a session also needs them valid, which only narrows it.
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    P,          \* principals (persons' devices, machines)
    S,          \* services
    Approvers,  \* Approvers[s]: who may approve access to s (signed policy)
    Durs,       \* durations a request may ask for
    MaxReq,     \* requests (state bound)
    MaxGrants,  \* grants signed (state bound)
    MaxPub,     \* revocation lists published (state bound)
    MaxTime,    \* clock bound
    CrlLife,    \* a revocation list's life at the agent
    Mutant

VARIABLES
    now,
    reqs,       \* reqs[i]: [p, s, d] or None
    approvals,  \* approvals the network carried: [id, by] (replayable)
    used,       \* request ids the issuer answered: granted or denied (its journal)
    denied,     \* request ids an approver denied (nfltr access deny: the final answer)
    grants,     \* <<[req, p, s, by, until, rev, revAt]>>
    pubs,       \* <<[at, rev]>>: the issuer's revocation lists, in order
    acrl,       \* the index of the list the agent holds
    sess,       \* open sessions [p, s, g]
    opened      \* history: grants a session was opened with

vars == <<now, reqs, approvals, used, denied, grants, pubs, acrl, sess, opened>>

None == [p |-> "none", s |-> "none", d |-> 0]

TypeOK ==
    /\ now \in 0..MaxTime
    /\ \A i \in 1..MaxReq : reqs[i] = None \/ reqs[i] \in [p : P, s : S, d : Durs]
    /\ approvals \subseteq [id : 1..MaxReq, by : P]
    /\ used \subseteq 1..MaxReq
    /\ denied \subseteq used
    /\ Len(grants) <= MaxGrants
    /\ acrl \in 1..Len(pubs)
    /\ \A x \in sess : x.p \in P /\ x.s \in S /\ x.g \in 1..Len(grants)

Init ==
    /\ now = 0
    /\ reqs = [i \in 1..MaxReq |-> None]
    /\ approvals = {}
    /\ used = {}
    /\ denied = {}
    /\ grants = <<>>
    /\ pubs = << [at |-> 0, rev |-> {}] >>
    /\ acrl = 1
    /\ sess = {}
    /\ opened = {}

Revoked == {g \in 1..Len(grants) : grants[g].rev}

\* A principal asks for a service.
Request(p, s, d) ==
    \E i \in 1..MaxReq :
        /\ reqs[i] = None
        /\ \A j \in 1..(i - 1) : reqs[j] # None
        /\ reqs' = [reqs EXCEPT ![i] = [p |-> p, s |-> s, d |-> d]]
        /\ UNCHANGED <<now, approvals, used, denied, grants, pubs, acrl, sess, opened>>

\* Anyone signs any request (the attacker's own key included): the issuer
\* judges the authority.
Approve(a, i) ==
    /\ reqs[i] # None
    /\ [id |-> i, by |-> a] \notin approvals
    /\ approvals' = approvals \cup {[id |-> i, by |-> a]}
    /\ UNCHANGED <<now, reqs, used, denied, grants, pubs, acrl, sess, opened>>

\* The issuer signs a grant for an approval the relay handed it (any
\* approval, any number of times).
Sign(ap, d) ==
    LET r == reqs[ap.id] IN
    /\ Len(grants) < MaxGrants
    /\ ap.id \notin used \/ Mutant = "issuer-no-replay-set"
                         \/ (Mutant = "issuer-signs-denied" /\ ap.id \in denied)
    /\ ap.by \in Approvers[r.s] \/ Mutant = "issuer-any-approver"
    /\ ap.by # r.p \/ Mutant = "self-approve"
    /\ d = r.d \/ Mutant = "dur-from-request"
    /\ now + d <= MaxTime
    /\ used' = used \cup {ap.id}
    /\ grants' = Append(grants, [req |-> ap.id, p |-> r.p, s |-> r.s, by |-> ap.by,
                                 at |-> now, until |-> now + d, rev |-> FALSE, revAt |-> 0])
    /\ UNCHANGED <<now, reqs, approvals, denied, pubs, acrl, sess, opened>>

\* An approver of the service denies a request the issuer has not
\* answered: the request's final answer (lead decision 2026-11-26), a
\* replayed approval of it signs nothing.
Deny(a, i) ==
    /\ reqs[i] # None
    /\ i \notin used
    /\ a \in Approvers[reqs[i].s]
    /\ used' = used \cup {i}
    /\ denied' = denied \cup {i}
    /\ UNCHANGED <<now, reqs, approvals, grants, pubs, acrl, sess, opened>>

\* An approver or the owner revokes a grant at the issuer.
Revoke(g) ==
    /\ ~grants[g].rev
    /\ grants' = [grants EXCEPT ![g].rev = TRUE, ![g].revAt = now]
    /\ UNCHANGED <<now, reqs, approvals, used, denied, pubs, acrl, sess, opened>>

\* The issuer publishes its revocation list (the CRL it already signs).
Publish ==
    /\ Len(pubs) < MaxPub
    /\ pubs[Len(pubs)].rev # Revoked \/ pubs[Len(pubs)].at < now
    /\ pubs' = Append(pubs, [at |-> now, rev |-> Revoked])
    /\ UNCHANGED <<now, reqs, approvals, used, denied, grants, acrl, sess, opened>>

\* The relay hands the agent a newer list, or never does.
Deliver(i) ==
    /\ i > acrl
    /\ acrl' = i
    /\ sess' = IF Mutant = "revoke-refuses-only" THEN sess
               ELSE {x \in sess : x.g \notin pubs[i].rev}
    /\ UNCHANGED <<now, reqs, approvals, used, denied, grants, pubs, opened>>

Fresh(t) == t < pubs[acrl].at + CrlLife \/ Mutant = "stale-list-admits"

\* A client presents grant g (any it saw: the relay offers any) for p and s.
Open(p, s, g) ==
    LET x == grants[g] IN
    /\ x.p = p \/ Mutant = "agent-any-principal"
    /\ x.s = s \/ Mutant = "agent-any-service"
    /\ now < x.until \/ Mutant = "agent-no-expiry-check"
    /\ g \notin pubs[acrl].rev \/ Mutant = "agent-no-rev-check"
    /\ Fresh(now)
    /\ [p |-> p, s |-> s, g |-> g] \notin sess
    /\ sess' = sess \cup {[p |-> p, s |-> s, g |-> g]}
    /\ opened' = opened \cup {g}
    /\ UNCHANGED <<now, reqs, approvals, used, denied, grants, pubs, acrl>>

Close(x) ==
    /\ sess' = sess \ {x}
    /\ UNCHANGED <<now, reqs, approvals, used, denied, grants, pubs, acrl, opened>>

\* Time passes; the agent's timers end what expired by its clock.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ sess' = {x \in sess :
                  /\ (now' < grants[x.g].until \/ Mutant = "expiry-refuses-only")
                  /\ (Fresh(now') \/ Mutant = "stale-list-keeps")}
    /\ UNCHANGED <<reqs, approvals, used, denied, grants, pubs, acrl, opened>>

Next ==
    \/ \E p \in P, s \in S, d \in Durs : Request(p, s, d)
    \/ \E a \in P, i \in 1..MaxReq : Approve(a, i)
    \/ \E ap \in approvals, d \in Durs : Sign(ap, d)
    \/ \E a \in P, i \in 1..MaxReq : Deny(a, i)
    \/ \E g \in 1..Len(grants) : Revoke(g)
    \/ Publish
    \/ \E i \in 1..Len(pubs) : Deliver(i)
    \/ \E p \in P, s \in S, g \in 1..Len(grants) : Open(p, s, g)
    \/ \E x \in sess : Close(x)
    \/ Tick

Spec == Init /\ [][Next]_vars

\* Fair: time passes, the issuer signs and publishes, the relay delivers
\* (an honest relay; the safety properties assume none of this).
LiveSpec == Spec /\ WF_vars(Tick)

---------------------------------------------------------------------------
\* Every open session is its grant's principal and service.
GrantedOnly == \A x \in sess : grants[x.g].p = x.p /\ grants[x.g].s = x.s

\* No session outlives its grant's until.
ExpiryBound == \A x \in sess : now < grants[x.g].until

\* A revoked grant's sessions end within CrlLife of the revoke, whatever
\* the relay withholds.
RevokeBound == \A x \in sess : grants[x.g].rev => now < grants[x.g].revAt + CrlLife

\* An approval yields at most one grant: a replayed approval neither
\* doubles nor extends access.
ApprovalOnce == \A g1, g2 \in 1..Len(grants) : g1 # g2 => grants[g1].req # grants[g2].req

\* Every grant is exactly the request an authorised approver, not the
\* requester, signed: nothing widened.
GrantMatchesApproval ==
    \A g \in 1..Len(grants) :
        LET x == grants[g] IN
        /\ [id |-> x.req, by |-> x.by] \in approvals
        /\ x.p = reqs[x.req].p /\ x.s = reqs[x.req].s /\ x.until = x.at + reqs[x.req].d
        /\ x.by \in Approvers[x.s] /\ x.by # x.p

\* A denied request is never granted, whatever approval the relay replays.
DenyFinal == \A g \in 1..Len(grants) : grants[g].req \notin denied

\* Every grant session ends (the agent's timer, not the client).
SessionsEnd == <>[](sess = {})

\* Witnesses: each must be violated (the state is reachable).
WitnessOpened == opened = {}
WitnessExpiredClosed == ~\E g \in opened : now >= grants[g].until /\ ~grants[g].rev
WitnessRevokedClosed == ~\E g \in opened : grants[g].rev /\ g \in pubs[acrl].rev
WitnessStaleClosed == ~\E g \in opened : ~grants[g].rev /\ now < grants[g].until /\ ~Fresh(now)
WitnessDenied == denied = {}
WitnessTwoGrants == ~\E g1, g2 \in 1..Len(grants) : g1 # g2 /\ grants[g1].p = grants[g2].p /\ grants[g1].s = grants[g2].s

\* The model's approvers: alice approves s1; s2 names both, so a
\* requester there is an approver too (self-approve has a target).
MCApprovers == [s \in S |-> IF s = "s1" THEN {"alice"} ELSE P]
=============================================================================
