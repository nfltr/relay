------------------------- MODULE RevokePush -------------------------
\* How fast a revoke reaches the revoked machine's peers (spec/enrol/
\* README.md "RevokePush.tla"): `nfltr org revoke` writes the CRL into the
\* issuer's directory; the issuer's service (orgenrol.Service) is woken by
\* the file-change notice of that write, reads the directory, and
\* publishes the CRL to the relay's mailbox; the append wakes every
\* verifier's parked long-poll (the push); each verifier takes the CRL and
\* cuts its sessions of the machine. Every step of that path is an event:
\* it takes the network's latency, modelled as "before time passes"
\* (EventBound). Each event may be lost (a notice the watcher never saw, a
\* push the relay lost or withheld); each has a bounded backstop: the
\* service's own round every ServeWait, the verifier's fresh read every
\* FollowEvery (BackstopBound). A relay withholding the backstop reads too
\* is Enrol.tla's RevocationBound (the CRL's NextUpdate, fail closed),
\* not modelled here. One revoked machine; its peers are the verifiers
\* (a client and an agent: both ends of its sessions, either path).
EXTENDS Integers, FiniteSets

CONSTANTS
    NV,           \* verifiers 1..NV: the revoked machine's peers
    MaxTime,
    ServeWait,    \* the service's round: its long-poll of the requests ends by then
    FollowEvery,  \* a verifier's backstop: a fresh read of the CRL this often
    MaxLost,      \* notices and pushes lost
    Mutant

Verifiers == 1..NV

VARIABLES
    now,
    revokedAt,  \* when the owner revoked the machine, -1 if not
    disk,       \* the CRL in the issuer's directory: 0 (before), 1 (lists the machine)
    wake,       \* a file-change notice the service has not taken
    svc,        \* the service: "wait" (parked in its round) or "read" (maintain read snap)
    snap,       \* the CRL maintain read
    roundAt,    \* when the service's current round began
    pub,        \* the CRL the relay's mailbox holds
    push,       \* push[v]: the mailbox's wake of v's long-poll, in flight
    seen,       \* seen[v]: the CRL v holds
    readAt,     \* readAt[v]: v's last fresh read
    sess,       \* the verifiers holding a session with the machine
    lostWake, lostPush,
    cuts        \* history: how sessions were cut ("push", "read")

vars == <<now, revokedAt, disk, wake, svc, snap, roundAt, pub, push, seen, readAt, sess, lostWake, lostPush, cuts>>

Lost == lostWake + lostPush
ServeBackstop == Mutant # "no-serve-backstop"
FollowBackstop == Mutant # "no-follow-backstop"

TypeOK ==
    /\ now \in 0..MaxTime
    /\ revokedAt \in -1..MaxTime
    /\ disk \in 0..1 /\ snap \in 0..1 /\ pub \in 0..1
    /\ wake \in BOOLEAN
    /\ svc \in {"wait", "read"}
    /\ roundAt \in 0..MaxTime
    /\ push \in [Verifiers -> BOOLEAN]
    /\ seen \in [Verifiers -> 0..1]
    /\ readAt \in [Verifiers -> 0..MaxTime]
    /\ sess \subseteq Verifiers
    /\ Lost \in 0..MaxLost
    /\ cuts \subseteq {"push", "read"}

Init ==
    /\ now = 0
    /\ revokedAt = -1
    /\ disk = 0 /\ snap = 0 /\ pub = 0
    /\ wake = FALSE
    /\ svc = "wait"
    /\ roundAt = 0
    /\ push = [v \in Verifiers |-> FALSE]
    /\ seen = [v \in Verifiers |-> 0]
    /\ readAt = [v \in Verifiers |-> 0]
    /\ sess = {}
    /\ lostWake = 0 /\ lostPush = 0
    /\ cuts = {}

\* Time passes only once every event in flight has happened (or was
\* lost): a notice is taken, a maintain finishes, a push is delivered.
\* And no backstop is overdue: the service's round ends by roundAt +
\* ServeWait, a verifier reads afresh by readAt + FollowEvery (a mutant
\* without that backstop lets time pass it).
Tick ==
    /\ now < MaxTime
    /\ ~wake
    /\ svc = "wait"
    /\ \A v \in Verifiers : ~push[v]
    /\ ServeBackstop => now + 1 <= roundAt + ServeWait
    /\ FollowBackstop => \A v \in Verifiers : now + 1 <= readAt[v] + FollowEvery
    /\ now' = now + 1
    /\ UNCHANGED <<revokedAt, disk, wake, svc, snap, roundAt, pub, push, seen, readAt, sess, lostWake, lostPush, cuts>>

\* nfltr org revoke (orgissuer.RevokeMachines): the CRL listing the
\* machine, written into the issuer's directory under its lock; the write
\* is the file-change notice (none under poll-only: the code before
\* 2026-11-16, which waited for the round).
Revoke ==
    /\ revokedAt = -1
    /\ revokedAt' = now
    /\ disk' = 1
    /\ wake' = (Mutant # "poll-only")
    /\ UNCHANGED <<now, svc, snap, roundAt, pub, push, seen, readAt, sess, lostWake, lostPush, cuts>>

\* The notice is lost (no watcher: it failed to start; an overflow).
LoseWake ==
    /\ wake /\ Lost < MaxLost
    /\ wake' = FALSE
    /\ lostWake' = lostWake + 1
    /\ UNCHANGED <<now, revokedAt, disk, svc, snap, roundAt, pub, push, seen, readAt, sess, lostPush, cuts>>

\* The service's round ends (a notice, a request, or ServeWait) and
\* maintain reads the directory. The notice is taken here, before the
\* read: one that comes during the maintain stays for the next round.
\* Under clear-wake-after-publish it is taken at the round's end, so a
\* notice that came during the maintain is dropped with it.
Read ==
    /\ svc = "wait"
    /\ svc' = "read"
    /\ snap' = disk
    /\ wake' = IF Mutant = "clear-wake-after-publish" THEN wake ELSE FALSE
    /\ UNCHANGED <<now, revokedAt, disk, roundAt, pub, push, seen, readAt, sess, lostWake, lostPush, cuts>>

\* maintain publishes what it read when the relay holds an older CRL (a
\* replace-keyed append: it wakes every parked long-poll), and the
\* service parks in its next round.
Publish ==
    /\ svc = "read"
    /\ svc' = "wait"
    /\ roundAt' = now
    /\ pub' = IF snap > pub THEN snap ELSE pub
    /\ push' = IF snap > pub THEN [v \in Verifiers |-> TRUE] ELSE push
    /\ wake' = IF Mutant = "clear-wake-after-publish" THEN FALSE ELSE wake
    /\ UNCHANGED <<now, revokedAt, disk, snap, seen, readAt, sess, lostWake, lostPush, cuts>>

\* v takes CRL n (only a newer one) and cuts its session of the machine
\* when n lists it (no-cut: it keeps it).
Take(v, n, how) ==
    /\ seen' = [seen EXCEPT ![v] = IF n > seen[v] THEN n ELSE seen[v]]
    /\ sess' = IF n = 1 /\ Mutant # "no-cut" THEN sess \ {v} ELSE sess
    /\ cuts' = IF n = 1 /\ v \in sess /\ Mutant # "no-cut" THEN cuts \cup {how} ELSE cuts

\* The push reaches v's parked long-poll (orgenrol follow, orgid.Follow).
Deliver(v) ==
    /\ push[v]
    /\ push' = [push EXCEPT ![v] = FALSE]
    /\ Take(v, pub, "push")
    /\ UNCHANGED <<now, revokedAt, disk, wake, svc, snap, roundAt, pub, readAt, lostWake, lostPush>>

\* The relay loses or withholds the push to v (a NAT, a long-poll not
\* parked at the append).
LosePush(v) ==
    /\ push[v] /\ Lost < MaxLost
    /\ push' = [push EXCEPT ![v] = FALSE]
    /\ lostPush' = lostPush + 1
    /\ UNCHANGED <<now, revokedAt, disk, wake, svc, snap, roundAt, pub, seen, readAt, sess, lostWake, cuts>>

\* v's backstop: a fresh read of the mailbox (FollowEvery).
FreshRead(v) ==
    /\ FollowBackstop
    /\ readAt' = [readAt EXCEPT ![v] = now]
    /\ Take(v, pub, "read")
    /\ UNCHANGED <<now, revokedAt, disk, wake, svc, snap, roundAt, pub, push, lostWake, lostPush>>

\* The machine opens a session with v; v admits it only while its CRL
\* does not list the machine (admit-after-crl: whatever its CRL).
Admit(v) ==
    /\ v \notin sess
    /\ Mutant = "admit-after-crl" \/ seen[v] = 0
    /\ sess' = sess \cup {v}
    /\ UNCHANGED <<now, revokedAt, disk, wake, svc, snap, roundAt, pub, push, seen, readAt, lostWake, lostPush, cuts>>

Next ==
    \/ Tick \/ Revoke \/ LoseWake \/ Read \/ Publish
    \/ \E v \in Verifiers : Deliver(v) \/ LosePush(v) \/ FreshRead(v) \/ Admit(v)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* No end that took the CRL holds a session of the machine: none is
\* admitted after, and the one it held is cut.
NoAdmitAfterLearn == \A v \in sess : seen[v] = 0

\* With no notice and no push lost, the revoke ends every session of the
\* machine before time passes: the network's latency, not a poll.
EventBound == (revokedAt # -1 /\ Lost = 0 /\ now > revokedAt) => sess = {}

\* With any losses, the backstops bound it: the service's round, then a
\* verifier's fresh read.
BackstopBound == (revokedAt # -1 /\ now > revokedAt + ServeWait + FollowEvery) => sess = {}

\* Witnesses (each must be violated: the states are reachable).
WitnessCutByPush == "push" \notin cuts
WitnessServeBackstop == ~(lostWake > 0 /\ pub = 1)
WitnessFollowBackstop == ~(lostPush > 0 /\ "read" \in cuts)
WitnessHeldAfterRevoke == ~(revokedAt # -1 /\ sess # {})
=============================================================================
