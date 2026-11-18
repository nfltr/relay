---------------------------- MODULE OrgHolds ----------------------------
\* The relay's holds on an organisation's shared mailboxes across a move
\* (the holds follow the fence: spec/orgmove/README.md "OrgHolds.tla"). OrgMove.tla checks the
\* organisation itself (one serving issuer, one history); this module
\* checks only what the relay lets each machine write.
\*
\* The issuer writes org.<id>.root, .crl and .answers (broadcasts) and
\* pulls and acks .enrol (a drop box): the relay's shared mailboxes
\* (relay-server spec/Reach.tla). Each is held by one
\* relay machine; a holder declaration takes a vacant hold, any other
\* machine is refused the holder's ops. One box stands for the four here:
\* the issuer touches them all the same way. Members' reads do not depend
\* on the hold (relay-server spec/Reach.tla SharedReadableByMembers) and
\* are not modelled, but the kind of the root box is: the relay makes a
\* shared mailbox a broadcast or a drop box at its first declared touch
\* (a holder's append or a member's pull: broadcast; a holder's pull or
\* ack: drop box; relay-server spec/Reach.tla KindOf) and never changes
\* it. Members read the root (the join, the keeper), so it must be a
\* broadcast: the issuer reads it back before it publishes (a newer CRL
\* of issuers the owner's machine published) as a member reads it. A
\* fresh relay holds no box yet (Init's kind None). Mutant holder-read
\* (relay org v0.1.3 to v0.1.6): that read declared the hold, so on a
\* fresh relay the root became a drop box and no machine could join.
\*
\* The design: `nfltr org move send` gives the holds up (the `release`
\* declaration: a holder's release vacates its own hold, anyone else's
\* changes nothing) only after the fence is committed AND no issuer
\* service runs on its directory (it takes the service's serve lock), so
\* no write of the old issuer, read before the fence, lands after the
\* release. The new machine's first holder declaration takes the vacant
\* holds. A compromised machine of the account (X) may take a vacant hold
\* first: the issuer is refused, visibly, the owner revokes X and the
\* relay vacates it (denial of service is outside the organisation's
\* threat model; integrity is the issuer's signatures, never the hold).
\*
\* A move back (the new machine sends the organisation back before it
\* ever published): the old machine's receive takes a bundle whose log
\* extends its own fenced log even while it still holds the moved keys,
\* and deletes them as it imports (nfltr org move finish is refused there
\* until the new machine publishes a CRL past the fence, so it cannot
\* clear the way). A move onto a machine whose own earlier move away
\* finished (its tombstone keeps the fenced log, no keys: the VM after
\* the organisation went back to the Mac) sets the tombstone aside and
\* imports.
EXTENDS Naturals

CONSTANTS
    MaxMoves,  \* moves started (state bound)
    MaxBad,    \* takes (and, under handover-to-anyone, releases) by X
    Mutant     \* "none" or a bug put back (scripts/spec-orgmove.sh holds)

A == "A"   \* the organisation's machine at first
B == "B"   \* the machine it moves to
X == "X"   \* another (compromised) machine of the relay account
None == "none"
Iss == {A, B}
Other(h) == IF h = A THEN B ELSE A

VARIABLES
    org,     \* org[h]: "none", "serving", "fenced" (a tombstone with the moved keys), "finished" (keys deleted)
    svc,     \* svc[h]: the issuer service (nfltr org serve, nfltr node): "off", "on", or "pending" (a publish it read under the directory lock and has not sent)
    step,    \* step[h]: nfltr org move send on h: "idle", "fenced", "locked" (holds the serve lock), "sent"
    hold,    \* the relay's hold on the shared box: None, A, B or X
    bundle,  \* the machine a sealed bundle in flight is addressed to, or None
    moves,   \* fences so far
    wrote,   \* wrote[h]: h's issuer published since it began serving (finish's guard reads the relay's CRL)
    early,   \* history: a finish before the other machine published
    bad,     \* X's acts so far
    kind     \* the root box at the relay: None (not made yet), "broadcast" or "dropbox"

vars == <<org, svc, step, hold, bundle, moves, wrote, early, bad, kind>>

\* A fresh relay (no box yet) or one A has published to.
Init ==
    /\ kind \in {None, "broadcast"}
    /\ org = [h \in Iss |-> IF h = A THEN "serving" ELSE "none"]
    /\ svc = [h \in Iss |-> "off"]
    /\ step = [h \in Iss |-> "idle"]
    /\ hold = IF kind = None THEN None ELSE A
    /\ bundle = None
    /\ moves = 0
    /\ wrote = [h \in Iss |-> h = A /\ kind # None]
    /\ early = FALSE
    /\ bad = 0

TypeOK ==
    /\ org \in [Iss -> {"none", "serving", "fenced", "finished"}]
    /\ svc \in [Iss -> {"off", "on", "pending"}]
    /\ step \in [Iss -> {"idle", "fenced", "locked", "sent"}]
    /\ hold \in {None, A, B, X}
    /\ bundle \in {None, A, B}
    /\ moves \in 0..MaxMoves
    /\ wrote \in [Iss -> BOOLEAN]
    /\ early \in BOOLEAN
    /\ bad \in 0..MaxBad
    /\ kind \in {None, "broadcast", "dropbox"}

----------------------------------------------------------------------------
\* The issuer service (orgenrol.Service.Run): it holds the serve lock while
\* it runs, reads the CRL and root under the directory's lock (refused once
\* the log ends in a fence: orgpki.ErrMoved) and publishes them after it,
\* declaring holder. A service starts only on a directory that serves.

SvcStart(h) ==
    /\ org[h] = "serving" /\ svc[h] = "off" /\ step[h] = "idle"
    /\ svc' = [svc EXCEPT ![h] = "on"]
    /\ UNCHANGED <<kind, org, step, hold, bundle, moves, wrote, early, bad>>

\* The read also reads the root back as a member (orgenrol readRoot): on
\* a fresh relay that makes the box a broadcast, vacant. Mutant
\* holder-read: the read declares the hold (a drop box, held by h).
SvcRead(h) ==
    /\ svc[h] = "on" /\ org[h] = "serving"
    /\ svc' = [svc EXCEPT ![h] = "pending"]
    /\ IF Mutant = "holder-read"
       THEN /\ kind' = IF kind = None THEN "dropbox" ELSE kind
            /\ hold' = IF hold = None THEN h ELSE hold
       ELSE /\ kind' = IF kind = None THEN "broadcast" ELSE kind
            /\ UNCHANGED hold
    /\ UNCHANGED <<org, step, bundle, moves, wrote, early, bad>>

\* The publish (mailbox append with the holder declaration): accepted when
\* h holds the box or it is vacant (the declaration takes it), refused
\* when another machine holds it (the service retries next round). A
\* publish read before the fence may land after it while h still holds
\* the box: the content was signed before the fence, and the release has
\* not run (it waits for the service to stop). So may one read before a
\* fence of the new machine's (a move back) take the vacant hold: the
\* release after it gives it up again (OldCannotWrite).
SvcWrite(h) ==
    /\ svc[h] = "pending"
    /\ svc' = [svc EXCEPT ![h] = "on"]
    /\ kind' = IF kind = None THEN "broadcast" ELSE kind
    /\ IF hold \in {h, None}
       THEN /\ hold' = h
            /\ wrote' = [wrote EXCEPT ![h] = TRUE]
       ELSE UNCHANGED <<hold, wrote>>
    /\ UNCHANGED <<org, step, bundle, moves, early, bad>>

\* The next round's read finds the fence: Run returns, the lock is free.
SvcStop(h) ==
    /\ svc[h] = "on" /\ org[h] # "serving"
    /\ svc' = [svc EXCEPT ![h] = "off"]
    /\ UNCHANGED <<kind, org, step, hold, bundle, moves, wrote, early, bad>>

----------------------------------------------------------------------------
\* nfltr org move send on h (orgissuer.Send, then orgcli): the fence under
\* the directory's lock; then the serve lock (waits until no service runs:
\* mutant old-keeps-writing skips the wait); then the release and the
\* bundle. Mutant release-without-fence: the holds are given up before the
\* fence, while the issuer still serves, and not after it.

Fence(h) ==
    /\ org[h] = "serving" /\ step[h] = "idle" /\ moves < MaxMoves
    /\ org' = [org EXCEPT ![h] = "fenced"]
    /\ step' = [step EXCEPT ![h] = "fenced"]
    /\ moves' = moves + 1
    /\ UNCHANGED <<kind, svc, hold, bundle, wrote, early, bad>>

EarlyRelease(h) ==
    /\ Mutant = "release-without-fence"
    /\ org[h] = "serving" /\ step[h] = "idle" /\ hold = h
    /\ hold' = None
    /\ UNCHANGED <<kind, org, svc, step, bundle, moves, wrote, early, bad>>

Lock(h) ==
    /\ step[h] = "fenced"
    /\ svc[h] = "off" \/ Mutant = "old-keeps-writing"
    /\ step' = [step EXCEPT ![h] = "locked"]
    /\ UNCHANGED <<kind, org, svc, hold, bundle, moves, wrote, early, bad>>

\* The release keeps a hold that is not h's (its postcondition: h holds
\* nothing), so a send run again, or one after X took the vacant hold,
\* changes nothing.
Release(h) ==
    /\ step[h] = "locked"
    /\ hold' = IF hold = h /\ Mutant # "release-without-fence" THEN None ELSE hold
    /\ step' = [step EXCEPT ![h] = "sent"]
    /\ bundle' = Other(h)
    /\ UNCHANGED <<kind, org, svc, moves, wrote, early, bad>>

\* nfltr org move receive on h: a machine with no organisation, its
\* finished tombstone, or (the move back) its fenced tombstone with the
\* moved keys, which the incoming log extends (OrgMove.tla checks the log;
\* one history here): the import deletes them. Mutant refuse-own-tombstone
\* (the code before): the keys there refuse it ("finish first"). Mutant
\* refuse-finished-tombstone (the VM's wrapper before,
\* org-issuer-remote.sh receive): any organisation directory refuses it.
Import(h) ==
    /\ bundle = h
    /\ \/ org[h] = "none"
       \/ org[h] = "finished" /\ Mutant # "refuse-finished-tombstone"
       \/ org[h] = "fenced" /\ Mutant # "refuse-own-tombstone"
    /\ org' = [org EXCEPT ![h] = "serving"]
    /\ step' = [step EXCEPT ![h] = "idle"]
    /\ wrote' = [wrote EXCEPT ![h] = FALSE]
    /\ bundle' = None
    /\ UNCHANGED <<kind, svc, hold, moves, early, bad>>

\* nfltr org move finish on h: deletes the moved keys once the relay holds
\* a CRL past the fence's (the other machine published). Mutant
\* finish-early: without that check.
Finish(h) ==
    /\ org[h] = "fenced" /\ step[h] = "sent"
    /\ wrote[Other(h)] \/ Mutant = "finish-early"
    /\ org' = [org EXCEPT ![h] = "finished"]
    /\ early' = (early \/ ~wrote[Other(h)])
    /\ UNCHANGED <<kind, svc, step, hold, bundle, moves, wrote, bad>>

----------------------------------------------------------------------------
\* X, another machine of the account: its holder declaration takes a vacant
\* hold; the owner revokes it and the relay vacates its holds. Mutant
\* handover-to-anyone: X's release vacates a hold that is not X's.

\* X's take is a holder's append (on a fresh relay it makes the broadcast);
\* X's holder pull of a box not yet made would make it a drop box: denial
\* of service, outside the threat model, not modelled.
XTake ==
    /\ hold = None /\ bad < MaxBad
    /\ hold' = X /\ bad' = bad + 1
    /\ kind' = IF kind = None THEN "broadcast" ELSE kind
    /\ UNCHANGED <<org, svc, step, bundle, moves, wrote, early>>

XRelease ==
    /\ Mutant = "handover-to-anyone"
    /\ hold \in Iss /\ bad < MaxBad
    /\ hold' = None /\ bad' = bad + 1
    /\ UNCHANGED <<kind, org, svc, step, bundle, moves, wrote, early>>

Revoke ==
    /\ hold = X
    /\ hold' = None
    /\ UNCHANGED <<kind, org, svc, step, bundle, moves, wrote, early, bad>>

Next ==
    \/ \E h \in Iss :
        \/ SvcStart(h) \/ SvcRead(h) \/ SvcWrite(h) \/ SvcStop(h)
        \/ Fence(h) \/ EarlyRelease(h) \/ Lock(h) \/ Release(h)
        \/ Import(h) \/ Finish(h)
    \/ XTake \/ XRelease \/ Revoke

Spec == Init /\ [][Next]_vars

\* Fair: services run, a send under way completes, a bundle is imported,
\* the owner revokes a machine that took a hold. Fence (the owner's choice
\* to move) and Finish are not.
LiveSpec ==
    /\ Spec
    /\ \A i \in Iss : (WF_vars(SvcStart(i)) /\ WF_vars(SvcRead(i)) /\ WF_vars(SvcWrite(i)) /\ WF_vars(SvcStop(i)))
    /\ \A i \in Iss : (WF_vars(Lock(i)) /\ WF_vars(Release(i)) /\ WF_vars(Import(i)))
    /\ WF_vars(Revoke)

----------------------------------------------------------------------------
\* Safety.

\* The old machine cannot write: once its send has run (the bundle is on
\* its way), it holds nothing; the holder declarations of the new machine
\* take the vacant holds.
OldCannotWrite == \A h \in Iss : (org[h] # "serving" /\ step[h] = "sent") => hold # h

\* At most one writer: a serving issuer's hold is neither taken nor
\* vacated by any other machine (an action property).
HolderKeeps == [][\A h \in Iss : (hold = h /\ org[h] = "serving") => hold' = h]_vars

\* Members can read the root: it is never a drop box.
RootReadable == kind # "dropbox"

\* finish deletes the moved keys only after the other machine published.
FinishAfterPublish == ~early

\* Liveness (LiveSpec): a bundle in flight ends with its machine serving,
\* holding the box and publishing, or moving the organisation on.
MoveCompletes ==
    \A h \in Iss : (bundle = h) ~> ((org[h] = "serving" /\ hold = h /\ wrote[h]) \/ (org[h] = "fenced" /\ bundle # h))

\* Witnesses (each must be violated: the states are reachable).
WitnessMoved == ~(org[B] = "serving" /\ hold = B /\ wrote[B])
WitnessMovedBack == ~(moves = 2 /\ org[A] = "serving" /\ hold = A /\ wrote[A])
WitnessBackUnpublished == ~(moves = 2 /\ org[A] = "serving" /\ ~wrote[B])
WitnessTakenVacant == ~(hold = X /\ org[B] = "serving")
WitnessLateWrite == ~(org[A] = "fenced" /\ svc[A] = "pending" /\ hold = A)
WitnessFinished == ~(org[A] = "finished" /\ hold = B)
\* The third move: a bundle on its way to B's finished tombstone.
WitnessReturnToFinished == ~(bundle = B /\ org[B] = "finished")
\* A fresh relay: the issuer's read made the root a broadcast before its first publish.
WitnessReadFirst == ~(kind = "broadcast" /\ hold = None /\ ~wrote[A] /\ moves = 0)
=============================================================================
