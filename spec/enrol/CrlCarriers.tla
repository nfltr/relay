---------------------------- MODULE CrlCarriers ----------------------------
\* How a member gets a current CRL when the mailbox is down (lane
\* MAILBOXSPOF, nfltr docs/decisions/crl-off-mailbox-2026-11-20.md;
\* spec/enrol/README.md "CrlCarriers.tla"). The issuer signs a CRL
\* (CrlLife, re-signed ReSign before its NextUpdate) and publishes it on
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
EXTENDS Integers, Sequences

CONSTANTS
    MaxTime,
    CrlLife,      \* NextUpdate - ThisUpdate (orgpki.CRLLife, 1 h)
    ReSign,       \* the issuer re-signs this long before NextUpdate (CRLLife/3)
    CopyEvery,    \* the issuer puts the copy again this often (orgenrol copyEvery)
    FollowEvery,  \* the member reads the copy this often (orgid.FollowEvery)
    Late,         \* the alert's slack past the re-sign time (relay crlLateSlack)
    MaxCrls,
    MaxOutages,   \* issuer outages, mailbox outages and relay restarts (each)
    Mutant

VARIABLES
    now,
    crls,       \* every CRL the issuer signed: <<[this, next, rev]>>, index = Number
    revokedAt,  \* when the owner revoked the machine, -1 if not
    issuerUp, upSince, downs,
    mailboxUp, mdowns,
    box,        \* the CRL Number the mailbox holds (0: none)
    copy,       \* the CRL Number the relay's copy holds (0: none: lost at a restart)
    sent,       \* the CRL Number the issuer last put on the copy (its own memory)
    putAt,      \* when the issuer last put the copy
    restarts,
    held,       \* the verifier's CRL: [num, next, rev] (num 0: one the relay made)
    learned,    \* the verifier once took a signed CRL listing the machine
    readAt,     \* when the verifier last read the copy
    sess,       \* the verifier holds a session of the machine
    renewal     \* the issuer's renewals: "none", "before" the revoke only, or one "after" it

vars == <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal>>

Last == crls[Len(crls)]
Rec(n) == [num |-> n, next |-> crls[n].next, rev |-> crls[n].rev]
Fresh == held.next > now

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
    /\ held' = IF Stale(viaCopy) THEN [Rec(n) EXCEPT !.next = now + CrlLife] ELSE Rec(n)
    /\ learned' = (learned \/ crls[n].rev)
    /\ sess' = (sess /\ ~crls[n].rev)
\* An unsigned CRL the relay made: fresh, listing nothing. Refused by the
\* signature check; taken only under copy-unsigned.
Forged == [num |-> 0, next |-> now + CrlLife, rev |-> FALSE]

\* The relay's alert: the copy past its re-sign time by Late. Under
\* alert-on-mailbox it is the mailbox's health instead.
Alert ==
    IF Mutant = "alert-on-mailbox" THEN ~mailboxUp
    ELSE copy # 0 /\ now > crls[copy].next - ReSign + Late

\* What must happen before time passes.
ReSignDue == issuerUp /\ Len(crls) < MaxCrls /\ Last.next - now <= ReSign
PutDue == issuerUp /\ Mutant # "mailbox-only" /\ (sent # Len(crls) \/ now - putAt >= CopyEvery)
BoxDue == issuerUp /\ mailboxUp /\ box # Len(crls)
PushDue == mailboxUp /\ box > held.num /\ crls[box].next > now
\* (A read due at the instant the issuer puts comes after the put: in the
\* code's continuous time a read just before it is FollowEvery before the
\* next, which the bound's margin, ReSign > CopyEvery + FollowEvery, is for.)
ReadDue == Mutant # "mailbox-only" /\ now - readAt >= FollowEvery /\ ~ReSignDue /\ ~PutDue

TypeOK ==
    /\ now \in 0..MaxTime
    /\ revokedAt \in -1..MaxTime
    /\ issuerUp \in BOOLEAN /\ mailboxUp \in BOOLEAN /\ sess \in BOOLEAN /\ learned \in BOOLEAN
    /\ box \in 0..Len(crls) /\ copy \in 0..Len(crls)
    /\ held.num \in 0..Len(crls)

Init ==
    /\ now = 0
    /\ crls = <<[this |-> 0, next |-> CrlLife, rev |-> FALSE]>>
    /\ revokedAt = -1
    /\ issuerUp = TRUE /\ upSince = 0 /\ downs = 0
    /\ mailboxUp = TRUE /\ mdowns = 0
    /\ box = 1 /\ copy = (IF Mutant = "mailbox-only" THEN 0 ELSE 1) /\ sent = 1 /\ putAt = 0 /\ restarts = 0
    /\ held = Rec(1) /\ learned = FALSE /\ readAt = 0
    /\ sess = FALSE /\ renewal = "none"

Tick ==
    /\ now < MaxTime
    /\ ~ReSignDue /\ ~PutDue /\ ~BoxDue /\ ~PushDue /\ ~ReadDue
    /\ now' = now + 1
    /\ sess' = (sess /\ held.next > now + 1)     \* fail closed at NextUpdate
    /\ UNCHANGED <<crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, renewal>>

\* The issuer (nfltr org serve, orgenrol.Service.maintain).
Republish ==
    /\ ReSignDue
    /\ crls' = Append(crls, [this |-> now, next |-> now + CrlLife, rev |-> Last.rev])
    /\ UNCHANGED <<now, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal>>
Revoke ==
    /\ issuerUp /\ revokedAt = -1 /\ Len(crls) < MaxCrls
    /\ revokedAt' = now
    /\ crls' = Append(crls, [this |-> now, next |-> now + CrlLife, rev |-> TRUE])
    /\ UNCHANGED <<now, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal>>
Publish ==
    /\ BoxDue
    /\ box' = Len(crls)
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal>>
PutCopy ==
    /\ PutDue
    /\ copy' = Len(crls) /\ sent' = Len(crls) /\ putAt' = now
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, restarts, held, learned, readAt, sess, renewal>>
\* A renewal (Enrol.tla Issue) is decided by the issuer's own log. Under
\* renew-by-copy it is decided by the CRL a carrier holds (the relay's
\* copy: an issuer restoring its revocations from it, or a renewal path
\* off the mailbox reading it), which can predate the revoke.
Renew ==
    /\ issuerUp
    /\ IF Mutant = "renew-by-copy" THEN copy # 0 /\ ~crls[copy].rev ELSE revokedAt = -1
    /\ renewal' = IF revokedAt # -1 \/ renewal = "after" THEN "after" ELSE "before"
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess>>

\* Outages: the issuer's process or its host; the mailbox service; a
\* relay restart (its copy is in memory).
IssuerDown ==
    /\ issuerUp /\ downs < MaxOutages
    /\ issuerUp' = FALSE /\ downs' = downs + 1
    /\ UNCHANGED <<now, crls, revokedAt, upSince, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal>>
IssuerBack ==
    /\ ~issuerUp
    /\ issuerUp' = TRUE /\ upSince' = now
    /\ UNCHANGED <<now, crls, revokedAt, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal>>
MailboxDown ==
    /\ mailboxUp /\ mdowns < MaxOutages
    /\ mailboxUp' = FALSE /\ mdowns' = mdowns + 1
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal>>
MailboxBack ==
    /\ ~mailboxUp
    /\ mailboxUp' = TRUE
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, sess, renewal>>
RelayRestart ==
    /\ restarts < MaxOutages /\ copy # 0
    /\ copy' = 0 /\ restarts' = restarts + 1
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, sent, putAt, held, learned, readAt, sess, renewal>>

\* The member (orgid.Follow): the mailbox's push, the copy's read.
Push ==
    /\ PushDue
    /\ Take(box, FALSE)
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, readAt, renewal>>
ReadCopy ==
    /\ ReadDue
    /\ readAt' = now
    /\ IF copy # 0 /\ TakeOK(copy, TRUE) THEN Take(copy, TRUE)
       ELSE UNCHANGED <<held, learned, sess>>
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, renewal>>
\* The relay serves CRL n (one it carried) on either carrier, when it likes.
Replay(n, viaCopy) ==
    /\ Take(n, viaCopy)
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, readAt, renewal>>
\* ... or one it made.
ServeForged ==
    /\ Mutant = "copy-unsigned"
    /\ held' = Forged
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, learned, readAt, sess, renewal>>

\* The machine presents its certificate; the verifier admits it on a
\* current CRL that does not list it.
Admit ==
    /\ ~sess /\ Fresh /\ ~held.rev
    /\ sess' = TRUE
    /\ UNCHANGED <<now, crls, revokedAt, issuerUp, upSince, downs, mailboxUp, mdowns, box, copy, sent, putAt, restarts, held, learned, readAt, renewal>>

Next ==
    \/ Tick \/ Republish \/ Revoke \/ Publish \/ PutCopy \/ Renew
    \/ IssuerDown \/ IssuerBack \/ MailboxDown \/ MailboxBack \/ RelayRestart
    \/ Push \/ ReadCopy \/ \E n \in 1..Len(crls), c \in BOOLEAN : Replay(n, c)
    \/ ServeForged \/ Admit

Spec == Init /\ [][Next]_vars

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
\* fires it; an issuer just back clears it at its put), and fires before a member's CRL lapses while the relay
\* holds a copy.
AlertOnlyOnIssuer == Alert => ~issuerUp \/ ReSignDue \/ PutDue
AlertBeforeLapse == (copy # 0 /\ crls[copy].next <= now) => Alert

\* Witnesses (each must be violated: reachable).
WitnessLapsed == Fresh
WitnessCopyWhileMailboxDown == ~(~mailboxUp /\ held.num > box)
WitnessAlert == ~Alert
WitnessLearned == ~learned
WitnessRestartWhileIssuerDown == ~(~issuerUp /\ copy = 0)
=============================================================================
