---------------------------- MODULE CrlCarriers ----------------------------
\* How a member gets a current CRL when the mailbox is down (lane
\* MAILBOXSPOF, nfltr docs/decisions/crl-off-mailbox-2026-11-20.md;
\* spec/enrol/README.md "CrlCarriers.tla"). The issuer signs a CRL
\* (CrlLife, re-signed every Every) and publishes it on
\* two carriers that fail apart: the mailbox (orgid.CRLMailbox, the
\* push) and the relay's own copy (relay-server /api/v1/org-crl/<org>,
\* in the relay's process: a relay restart loses it, the issuer puts it
\* again every CopyEvery). A member (the verifier) takes the mailbox's
\* push and reads the copy every FollowEvery; both go through one rule
\* (orgid.Verifier.TakeCRL): signed by the issuer under the trusted root,
\* newer than the CRL held, NextUpdate not passed. The relay is the
\* attacker for both carriers: it may withhold, replay any CRL it ever
\* carried and serve one it made (unsigned). The relay's alert
\* (nfltr_relay_org_crl_copies{freshness="late"}) fires when the copy is
\* past its re-sign time: the issuer stopped re-signing or stopped
\* reaching the relay, never because the mailbox is down.
\*
\* Time passes (Tick) only once nothing urgent is left (as RevokePush.tla):
\* an issuer that is up re-signs when due and puts the copy when it
\* changed or CopyEvery passed; the mailbox, when up, takes the publish
\* and pushes it; the member's read of the copy is due every FollowEvery.
\* One machine, revoked or not; one verifier. The ordering of CRLs and the
\* revocation bound across renewals and rotations are Enrol.tla's: this
\* model checks only that a second carrier keeps them and adds the
\* availability it is for.
\*
\* Replicas (lane MAILBOXSPOF2): a relay of several replicas keeps the
\* copy in each; a put lands on any one of them, which keeps it and
\* publishes it on the replicas' bus (relay-server's Redis pub/sub,
\* as its revocations), and every other replica keeps it on delivery
\* (Deliver, before time passes: milliseconds against minutes). A member's
\* read lands on any replica. A restart loses a replica's copy and what
\* the bus sent it meanwhile (pub/sub keeps nothing for a subscriber that
\* was away: a resubscribe is modelled as a restart, which loses more).
\* The alert is per replica: its copy late (OrgIssuerUnreachable), or the
\* replica held a copy and has not held one again for Vanish since its
\* restart (OrgCRLCopyVanished: the monitoring remembers the copies'
\* count): an issuer that is up puts it again within CopyEvery < Vanish.
EXTENDS Integers, Sequences, TLC

CONSTANTS
    MaxTime,
    CrlLife,      \* NextUpdate - ThisUpdate (orgpki.CRLLife, 24 h)
    Every,        \* the issuer re-signs a CRL this old (orgpki.CRLEvery, 1 h)
    CopyEvery,    \* the issuer puts the copy again this often (orgenrol copyEvery)
    FollowEvery,  \* the member reads the copy this often (orgid.FollowEvery)
    Late,         \* the alert's slack past the re-sign time (relay crlLateSlack)
    MaxCrls,
    MaxOutages,   \* issuer outages, mailbox outages and relay restarts (each)
    Replicas,     \* the relay's replicas (a set)
    Vanish,       \* a replica's copy gone this long counts for the alert (OrgCRLCopyVanished's for)
    WarnAge,      \* a member warns once its CRL is this old (orgid.CRLWarnAge, 2 h)
    Ride,         \* the issuer outage no session may notice (CrlLife - Every - CopyEvery - FollowEvery)
    FreshAge,     \* the verifier's service is fresh-bounded: its sessions end once the CRL held is this old (nfltr up fresh:; 0: no key)
    Mutant

VARIABLES
    now,
    crls,       \* every CRL the issuer signed: <<[this, next, rev]>>, index = Number
    revokedAt,  \* when the owner revoked the machine, -1 if not
    issuerUp, upSince, downs,
    mailboxUp, mdowns,
    box,        \* the CRL Number the mailbox holds (0: none)
    copy,       \* replica -> the CRL Number its copy holds (0: none: lost at a restart)
    bus,        \* replica -> the put the bus is delivering to it (0: none)
    landed,     \* the replica the issuer's last put landed on
    sent,       \* the CRL Number the issuer last put on the copy (its own memory)
    putAt,      \* when the issuer last put the copy
    restarts,
    lostAt,     \* replica -> when a restart lost its copy, -1 once it holds one again
    restartAt,  \* when a replica last restarted (-1: never)
    peerTook,   \* the verifier took a CRL from a replica the put did not land on
    held,       \* the verifier's CRL: [num, next, rev] (num 0: one the relay made)
    learned,    \* the verifier once took a signed CRL listing the machine
    readAt,     \* when the verifier last read the copy
    sess,       \* the verifier holds a session of the machine
    renewal,    \* the issuer's renewals: "none", "before" the revoke only, or one "after" it
    downAt,     \* when the issuer last went down (-1: never)
    mupSince    \* when the mailbox last came back (0: up from the start)

vars == <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal, bus, landed, lostAt, restartAt, peerTook, downAt, mupSince>>
relay == <<bus, landed, lostAt, restartAt, peerTook>>
clocks == <<downAt, mupSince>>

\* ReSign: the issuer re-signs this long before NextUpdate. The design
\* before ISSUEROUT (hour-life) signed a CRL valid a little longer than
\* its re-sign interval (1 h, re-signed with 20 minutes left): an issuer
\* outage past it refused every session.
Life == IF Mutant = "hour-life" THEN Every + 1 ELSE CrlLife
ReSign == Life - Every
ASSUME Every + CopyEvery + FollowEvery < WarnAge /\ WarnAge < CrlLife
ASSUME Ride <= CrlLife - Every - CopyEvery - FollowEvery
\* A service's freshness bound (nfltr up fresh:, lane SECFIX item 8): at
\* least WarnAge (orgid.FreshMin = CRLWarnAge, 2 h), at most the CRL's
\* life. Below the re-sign interval and the copy's lag (fresh-short: the
\* bound at Every) it cuts the service's sessions every re-sign while the
\* issuer is up (FreshQuiet).
ASSUME FreshAge = 0 \/ FreshAge \in WarnAge..CrlLife

\* The fresh-bounded service admits and holds a session only while the
\* CRL held at t was signed less than its bound ago (orgid.FreshBound:
\* until is ThisUpdate + fresh; a newer CRL taken moves it, Hold's check
\* on the change). fresh-ignored: the key read, the bound not applied.
Bound == IF Mutant = "fresh-short" THEN Every ELSE FreshAge
Within(t) == FreshAge = 0 \/ Mutant = "fresh-ignored" \/ t - held.this < Bound

Last == crls[Len(crls)]
Rec(n) == [num |-> n, this |-> crls[n].this, next |-> crls[n].next, rev |-> crls[n].rev]
Fresh == held.next > now
\* The member's warning (orgid.CRLStale): its CRL signed WarnAge ago or
\* more. Under warn-on-lapse (the design before ISSUEROUT) nothing is said
\* until the CRL lapses; under warn-early it warns at the re-sign age.
Warn ==
    CASE Mutant = "warn-on-lapse" -> ~Fresh
      [] Mutant = "warn-early" -> now - held.this >= Every
      [] OTHER -> now - held.this >= WarnAge

\* The one take rule, whatever carried the CRL (orgid.Verifier.TakeCRL).
\* Under the copy-path mutants the copy is taken by another rule: a lapsed
\* CRL kept as valid for CrlLife from its read (stale-copy: a cache's TTL
\* in place of the NextUpdate: each read of the
\* same CRL extends it), an older one (copy-rollback), one the
\* relay made (copy-unsigned, Forged).
Stale(viaCopy) == viaCopy /\ Mutant = "stale-copy"
TakeOK(n, viaCopy) ==
    \/ /\ n > held.num \/ (viaCopy /\ Mutant = "copy-rollback" /\ n # held.num)
       /\ crls[n].next > now
    \/ Stale(viaCopy) /\ n >= held.num
Take(n, viaCopy) ==
    /\ TakeOK(n, viaCopy)
    /\ held' = IF Stale(viaCopy) THEN [Rec(n) EXCEPT !.next = now + Life] ELSE Rec(n)
    /\ learned' = (learned \/ crls[n].rev)
    /\ sess' = (sess /\ ~crls[n].rev)
\* An unsigned CRL the relay made: fresh, listing nothing. Refused by the
\* signature check; taken only under copy-unsigned.
Forged == [num |-> 0, this |-> now, next |-> now + Life, rev |-> FALSE]

\* The relay's alert: a replica's copy past its re-sign time by Late
\* (OrgIssuerUnreachable), or a replica whose copy a restart lost and no
\* put brought back for Vanish (OrgCRLCopyVanished; alert-forgets, the
\* design before MAILBOXSPOF2, has no such memory). Under
\* alert-on-mailbox it is the mailbox's health instead.
AlertAt(r) ==
    \/ copy[r] # 0 /\ now > crls[copy[r]].this + Every + Late
    \/ Mutant # "alert-forgets" /\ lostAt[r] # -1 /\ now >= lostAt[r] + Vanish
Alert ==
    IF Mutant = "alert-on-mailbox" THEN ~mailboxUp
    ELSE \E r \in Replicas : AlertAt(r)

\* What must happen before time passes.
ReSignDue == issuerUp /\ Len(crls) < MaxCrls /\ now - Last.this >= Every
PutDue == issuerUp /\ Mutant # "mailbox-only" /\ (sent # Len(crls) \/ now - putAt >= CopyEvery)
BoxDue == issuerUp /\ mailboxUp /\ box # Len(crls)
DeliverDue == \E r \in Replicas : bus[r] # 0
\* (push-dropped: the mailbox drops a revoking CRL silently: no error,
\* no push; only the copy's read carries it.)
PushDue == mailboxUp /\ box > held.num /\ crls[box].next > now /\ ~(Mutant = "push-dropped" /\ crls[box].rev)
\* (A read due at the instant the issuer puts comes after the put: in the
\* code's continuous time a read just before it is FollowEvery before the
\* next, which the bound's margin, ReSign > CopyEvery + FollowEvery, is for.)
ReadDue == Mutant # "mailbox-only" /\ now - readAt >= FollowEvery /\ ~ReSignDue /\ ~PutDue /\ ~DeliverDue

TypeOK ==
    /\ now \in 0..MaxTime
    /\ revokedAt \in -1..MaxTime
    /\ issuerUp \in BOOLEAN /\ mailboxUp \in BOOLEAN /\ sess \in BOOLEAN /\ learned \in BOOLEAN
    /\ box \in 0..Len(crls)
    /\ copy \in [Replicas -> 0..Len(crls)] /\ bus \in [Replicas -> 0..Len(crls)]
    /\ landed \in Replicas /\ peerTook \in BOOLEAN
    /\ lostAt \in [Replicas -> -1..MaxTime] /\ restartAt \in -1..MaxTime
    /\ held.num \in 0..Len(crls)

Init ==
    /\ now = 0
    /\ crls = <<[this |-> 0, next |-> Life, rev |-> FALSE]>>
    /\ revokedAt = -1
    /\ issuerUp = TRUE /\ upSince = 0 /\ downs = 0
    /\ mailboxUp = TRUE /\ mdowns = 0
    /\ box = 1 /\ copy = [r \in Replicas |-> IF Mutant = "mailbox-only" THEN 0 ELSE 1] /\ sent = 1 /\ putAt = 0 /\ restarts = 0
    /\ bus = [r \in Replicas |-> 0] /\ landed \in Replicas /\ lostAt = [r \in Replicas |-> -1] /\ restartAt = -1 /\ peerTook = FALSE
    /\ held = Rec(1) /\ learned = FALSE /\ readAt = 0
    /\ sess = FALSE /\ renewal = "none"
    /\ downAt = -1 /\ mupSince = 0

Tick ==
    /\ now < MaxTime
    /\ ~ReSignDue /\ ~PutDue /\ ~BoxDue /\ ~PushDue /\ ~ReadDue /\ ~DeliverDue
    /\ now' = now + 1
    /\ sess' = (sess /\ (held.next > now + 1 \/ Mutant = "lapsed-accepted") /\ Within(now + 1))     \* fail closed at NextUpdate, and at the service's bound
    /\ UNCHANGED <<crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, renewal, relay, clocks>>

\* The issuer (nfltr org serve, orgenrol.Service.maintain).
Republish ==
    /\ ReSignDue
    /\ crls' = Append(crls, [this |-> now, next |-> now + Life, rev |-> Last.rev])
    /\ UNCHANGED <<now, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal, relay, clocks>>
Revoke ==
    /\ issuerUp /\ revokedAt = -1 /\ Len(crls) < MaxCrls
    /\ revokedAt' = now
    /\ crls' = Append(crls, [this |-> now, next |-> now + Life, rev |-> TRUE])
    /\ UNCHANGED <<now, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal, relay, clocks>>
Publish ==
    /\ BoxDue
    /\ box' = Len(crls)
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal, relay, clocks>>
\* The put lands on replica r, which keeps it and publishes it to the
\* others (relay-server orgCRLCopies, the bus); under one-replica (the
\* design before MAILBOXSPOF2) the others never get it.
PutCopy(r) ==
    /\ PutDue
    /\ copy' = [copy EXCEPT ![r] = Len(crls)] /\ sent' = Len(crls) /\ putAt' = now
    /\ bus' = [x \in Replicas |-> IF x = r \/ Mutant = "one-replica" THEN bus[x] ELSE Len(crls)]
    /\ landed' = r /\ lostAt' = [lostAt EXCEPT ![r] = -1]
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, restarts, held, learned, readAt, sess, renewal, restartAt, peerTook, clocks>>
\* A peer replica keeps the put the bus delivered (relay-server
\* runOrgCRLCopies) unless it holds a newer one: a put that landed on it
\* directly after the one the bus was carrying (deliver-lww, last writer
\* wins: the older delivery replaced the newer put and the replica served
\* a stale copy, late while the issuer is up; TLC's first counterexample
\* of this design, MAILBOXSPOF2).
Kept(r) == IF Mutant = "deliver-lww" \/ bus[r] >= copy[r] THEN bus[r] ELSE copy[r]
Deliver(r) ==
    /\ bus[r] # 0
    /\ copy' = [copy EXCEPT ![r] = Kept(r)] /\ bus' = [bus EXCEPT ![r] = 0] /\ lostAt' = [lostAt EXCEPT ![r] = -1]
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, sent, putAt, restarts, held, learned, readAt, sess, renewal, landed, restartAt, peerTook, clocks>>
\* A renewal (Enrol.tla Issue) is decided by the issuer's own log. Under
\* renew-by-copy it is decided by the CRL a carrier holds (the relay's
\* copy: an issuer restoring its revocations from it, or a renewal path
\* off the mailbox reading it), which can predate the revoke.
Renew ==
    /\ issuerUp
    /\ IF Mutant = "renew-by-copy" THEN \E r \in Replicas : copy[r] # 0 /\ ~crls[copy[r]].rev ELSE revokedAt = -1
    /\ renewal' = IF revokedAt # -1 \/ renewal = "after" THEN "after" ELSE "before"
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, relay, clocks>>

\* Outages: the issuer's process or its host; the mailbox service; a
\* relay restart (its copy is in memory).
IssuerDown ==
    /\ issuerUp /\ downs < MaxOutages
    /\ issuerUp' = FALSE /\ downs' = downs + 1 /\ downAt' = now
    /\ UNCHANGED <<now, crls, revokedAt, upSince, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal, relay, mupSince>>
IssuerBack ==
    /\ ~issuerUp
    /\ issuerUp' = TRUE /\ upSince' = now
    /\ UNCHANGED <<now, crls, revokedAt, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal, relay, clocks>>
MailboxDown ==
    /\ mailboxUp /\ mdowns < MaxOutages
    /\ mailboxUp' = FALSE /\ mdowns' = mdowns + 1
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal, relay, clocks>>
MailboxBack ==
    /\ ~mailboxUp
    /\ mailboxUp' = TRUE /\ mupSince' = now
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal, relay, downAt>>
RelayRestart(r) ==
    /\ restarts < MaxOutages /\ copy[r] # 0
    /\ copy' = [copy EXCEPT ![r] = 0] /\ bus' = [bus EXCEPT ![r] = 0] /\ restarts' = restarts + 1
    /\ lostAt' = [lostAt EXCEPT ![r] = now] /\ restartAt' = now
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, sent, putAt, held, learned, readAt, sess, renewal, landed, peerTook, clocks>>

\* The member (orgid.Follow): the mailbox's push, the copy's read.
Push ==
    /\ PushDue
    /\ Take(box, FALSE)
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, readAt, renewal, relay, clocks>>
\* (the read lands on any replica r)
ReadCopy(r) ==
    /\ ReadDue
    /\ readAt' = now
    /\ IF copy[r] # 0 /\ TakeOK(copy[r], TRUE)
       THEN Take(copy[r], TRUE) /\ peerTook' = (peerTook \/ r # landed)
       ELSE UNCHANGED <<held, learned, sess, peerTook>>
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, renewal, bus, landed, lostAt, restartAt, clocks>>
\* The relay serves CRL n (one it carried) on either carrier, when it likes.
Replay(n, viaCopy) ==
    /\ Take(n, viaCopy)
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, readAt, renewal, relay, clocks>>
\* ... or one it made.
ServeForged ==
    /\ Mutant = "copy-unsigned"
    /\ held' = Forged
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, learned, readAt, sess, renewal, relay, clocks>>

\* The machine presents its certificate; the verifier admits it on a
\* current CRL that does not list it.
Admit ==
    /\ ~sess /\ (Fresh \/ Mutant = "lapsed-accepted") /\ ~held.rev /\ Within(now)
    /\ sess' = TRUE
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, renewal, relay, clocks>>

Next ==
    \/ Tick \/ Republish \/ Revoke \/ Publish \/ Renew
    \/ \E r \in Replicas : PutCopy(r) \/ Deliver(r) \/ RelayRestart(r) \/ ReadCopy(r)
    \/ IssuerDown \/ IssuerBack \/ MailboxDown \/ MailboxBack
    \/ Push \/ \E n \in 1..Len(crls), c \in BOOLEAN : Replay(n, c)
    \/ ServeForged \/ Admit

Spec == Init /\ [][Next]_vars

\* The replicas are interchangeable (CrlCarriersReplicas.cfg's SYMMETRY).
ReplicaPerms == Permutations(Replicas)

----------------------------------------------------------------------------
\* Safety: a second carrier keeps Enrol.tla's revocation properties.

\* CrlLife after the revoke the verifier holds no session of the machine,
\* whatever either carrier delivered.
RevocationBound == sess => revokedAt = -1 \/ now < revokedAt + CrlLife
\* Once the verifier took a CRL listing the machine it holds no session.
RevokedMachineRefused == learned => ~sess
\* No session on a lapsed CRL.
NoSessionOnLapsed == sess => Fresh
\* The issuer renews nothing after the revoke (its log decides).
NoRenewAfterRevoke == renewal # "after"

\* Availability: with the issuer up for longer than CopyEvery + FollowEvery
\* (a relay restart right after it came back: the put again, then the read), the verifier holds a
\* current CRL, whether the mailbox is up or not (CopyEvery + FollowEvery
\* < ReSign: the copy lost at a restart is back and read before the CRL
\* held lapses). mailbox-only (the design before: the mailbox the only
\* carrier) breaks it.
CurrentWithoutMailbox == (issuerUp /\ now > upSince + CopyEvery + FollowEvery) => Fresh

\* The alert fires only while the issuer is down (a mailbox outage never
\* fires it; an issuer just back clears it at its put and the bus's
\* delivery), and fires before a member's CRL lapses while the relay
\* holds a copy.
AlertOnlyOnIssuer == Alert => ~issuerUp \/ ReSignDue \/ PutDue \/ DeliverDue
AlertBeforeLapse == \A r \in Replicas : (copy[r] # 0 /\ crls[copy[r]].next <= now) => Alert
\* The alert survives a relay restart during an issuer outage: with the
\* issuer down past its last put's re-sign time it fires (once Vanish has
\* passed since the last restart), whichever replicas restarted.
\* alert-forgets breaks it.
AlertWhileIssuerDown ==
    (~issuerUp /\ now > crls[sent].this + Every + Late /\ (restartAt = -1 \/ now >= restartAt + Vanish)) => Alert

\* Issuer outages (lane ISSUEROUT, nfltr
\* docs/decisions/issuer-outage-2026-11-25.md). The push bound: while the
\* push path works (the issuer and the mailbox up throughout since the
\* revoke) the verifier holds no session of the revoked machine once time
\* passes (RevokePush.tla bounds the push in seconds); RevocationBound
\* above is the worst case (CrlLife). push-dropped breaks it.
PushBound ==
    (revokedAt # -1 /\ now > revokedAt /\ issuerUp /\ upSince <= revokedAt /\ mailboxUp /\ mupSince <= revokedAt)
        => ~sess
\* An issuer outage shorter than Ride, with the issuer up long enough
\* before it for the member to hold its last CRL, leaves the verifier a
\* current CRL: no session is refused. hour-life breaks it.
RideOutage ==
    (~issuerUp /\ downAt > upSince + CopyEvery + FollowEvery /\ now < downAt + Ride) => Fresh
\* The member's warning: never while the issuer has been up longer than
\* CopyEvery + FollowEvery (warn-early breaks it), and always once the
\* issuer has been down WarnAge (warn-on-lapse breaks it).
QuietWhileIssuerUp == (issuerUp /\ now > upSince + CopyEvery + FollowEvery) => ~Warn
WarnWhileIssuerDown == (~issuerUp /\ now >= downAt + WarnAge) => Warn

\* A fresh-bounded service (lane SECFIX item 8): no session of it admitted
\* or held while the CRL held is FreshAge old or older, whatever the relay
\* withholds (fresh-ignored breaks it); and none cut for it while the
\* issuer is up past CopyEvery + FollowEvery (fresh-short breaks it).
FreshBound == (sess /\ FreshAge # 0) => now - held.this < FreshAge
FreshQuiet == (FreshAge # 0 /\ issuerUp /\ now > upSince + CopyEvery + FollowEvery) => now - held.this < Bound

\* Witnesses (each must be violated: reachable).
WitnessLapsed == Fresh
WitnessCopyWhileMailboxDown == ~(~mailboxUp /\ held.num > box)
WitnessAlert == ~Alert
WitnessLearned == ~learned
WitnessRestartWhileIssuerDown == ~(~issuerUp /\ \A r \in Replicas : copy[r] = 0)
WitnessAlertWithoutCopy == ~(Alert /\ \A r \in Replicas : copy[r] = 0)
WitnessPeerCopy == ~peerTook
WitnessRodeOutage == ~(~issuerUp /\ downAt > upSince + CopyEvery + FollowEvery /\ now = downAt + Ride - 1 /\ Fresh)
WitnessWarned == ~(Warn /\ Fresh)
WitnessRevokedPastPush == ~(revokedAt # -1 /\ now > revokedAt /\ sess)
\* CrlCarriersFresh.cfg: a current CRL too old for the service (its
\* sessions refused where an unbounded one admits), and a session held
\* to the last step before the bound.
WitnessFreshRefused == ~(FreshAge # 0 /\ Fresh /\ now - held.this >= FreshAge)
WitnessFreshHeld == ~(FreshAge # 0 /\ sess /\ now - held.this = FreshAge - 1)
=============================================================================
