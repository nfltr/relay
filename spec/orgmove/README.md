# Moving an organisation to another machine in TLA+ (2026-11-13)

The organisation's issuer
directory (the hash-chained audit log, the issuer key, the CRL, the answers
spool; not the root, which stays with its owner and renews the issuer from
there; not the machine-key root and store `a2a-root.key` and
`a2a-machines.json` beside it) moves from one machine to another as an
encrypted bundle, and a fence line in the log stops the old machine. The old machine
appends the fence, naming the new machine's single-use receive key, under
the issuer directory's lock; from then its issuer commits nothing. It sends
the fenced log and the keys sealed to that key, again until the new machine
serves (the relay may lose, withhold or replay the bundle; the owner may
carry it as a file instead). The new machine imports only a bundle whose
last line is a fence naming its own receive key, deletes that key as it
appends its arrival, and serves under the same issuer key, so the fleet's
certificates and CRLs do not change. `OrgMove.tla` is the design, checked
before any code. The transfer's secrecy and authenticity (the receive key
out of band, HPKE, the root pin) is `spec/proverif/orgmove.pv`; the fleet's
side of the CRL (take a newer Number only) is `spec/enrol/Enrol.tla`'s Take,
restated here.

## Invariants and properties

| property | means | mutant that breaks it |
|---|---|---|
| AtMostOneIssuer | at most one host can act as the issuer at any time: no overlap at all | `no-fence` (an export that copies the directory and leaves the old host serving), `serve-after-fence` (the issuer ignores its own fence), `fence-names-no-recipient` (the fence binds no receive key: two hosts import) |
| OldCannotIssue | in every log, the line after a fence is its recipient's arrival: the old host commits nothing after it fenced | `serve-after-fence` |
| AuditContinuous | every directory's log is a prefix of the one history of acts: no fork, no act lost across the move | `import-unfenced` (a backup or early copy is imported), `reusable-receive-key` (after the new host's disk is lost, the same bundle is imported again: an older state) |
| TokenOnce | each token is redeemed at most once, across every host | `no-fence`, `fence-names-no-recipient`, `reusable-receive-key` |
| CRLMonotone | one content per CRL Number, and a higher Number lists every name a lower one did: CRLs never go backwards | `no-fence`, `import-unfenced` |
| RevokedStaysRevoked | a name the fleet has seen revoked stays revoked for it | `import-unfenced` |
| FleetUnderServingIssuer | the serving issuer is the key the fleet's certificates chain through (verifiers hold CRLs by issuer key, relay client `orgid/verify.go`): machines keep their sessions and renew into it on their own | `rekey-on-import` |
| MoveCompletes (LiveSpec) | a fenced move ends with a host serving again | `no-resend` (one send: a bundle the relay lost is never made good), `ephemeral-receive-key` (the receive key kept in memory: a crash of the new host before the import strands the move) |

A restore from a backup (`Revive`, `OrgMoveRestore.cfg`: two hosts, two
restores, so a copy restored again after the restored host is lost is
checked too) takes a copy of any age: before its fence the copy takes the
newest published CRL as input (a `restore` line resuming its CRL Number at
that CRL's, `mrev` lines merging that CRL's revocations the copy lacks,
every token made before it void). It keeps AtMostOneIssuer,
OldCannotIssue, CRLMonotone, RevokedStaysRevoked, TokenOnce (a token the
lost host redeemed after the copy is void in it; token ids are fresh
across the history, 128 random bits) and FleetUnderServingIssuer;
AuditContinuous is not claimed under it (acts the lost host committed
after the copy are lost). Mutants (`restore-mutants.txt`): `revive-behind`
(no restore line: CRLMonotone, RevokedStaysRevoked), `merge-skipped` (the
Number resumed, the revocations not merged: RevokedStaysRevoked,
CRLMonotone), `number-not-above-published` (the revocations merged, the
Number the copy's own: CRLMonotone), `revive-keeps-tokens` (the copy's
tokens still answered: TokenOnce), `revive-while-held` (restored while a
host holds the organisation: AtMostOneIssuer). Witnesses
`WitnessRevivedTaken` (the restored issuer signs a CRL the fleet takes),
`WitnessBehindRestored` (a copy behind the published CRL restored, the
fleet taking a CRL above it), `WitnessRevocationMerged`,
`WitnessTokenVoided` (a token the lost host redeemed, void in the
restored log).

Witnesses (each must be violated, the state reachable): `WitnessMoved`,
`WitnessTokenAcrossMove` (a token made before the move is redeemed after
it), `WitnessRevokedAcrossMove` (a CRL the new host signs lists a revoke
from before the move), `WitnessResentAfterLoss`, `WitnessOldWiped`,
`WitnessCrashedThenMoved`, `WitnessBackupRefused` (a stale copy exists and
is not imported).

## `OrgMove.tla`

| Action | design (phase 2 code) |
|---|---|
| MakeToken, Redeem, Revoke, SignCRL | the issuer's acts (`orgpki.Issuer`), each committed to the log under the directory's lock; a host acts only while its log does not end in a fence |
| Commit | not a step of its own: the one log append MakeToken, Redeem, Revoke, SignCRL and Fence share |
| Fence | `nfltr org move send`, first half: under the lock, the fence line naming the receive key (after a fresh CRL: the move then has the CRL's hour) |
| Send | ... second half: the fenced log and the keys sealed (`crypto/hpke`) to that key, through the relay mailbox `org.<org>.move` or to a file; again until the new host serves |
| Backup | a copy that is not a move: a backup, a disk image, a bundle made before the fence |
| LoseBundle | the relay loses or withholds a bundle (bounded by MaxLostB) |
| Import | `nfltr org move receive`: opens a bundle sealed to its receive key, imports it only when the log ends in the fence naming that key, deletes the receive key as the arrival line commits, serves |
| Wipe | the owner, after `nfltr org status` on the new host shows it serving, deletes the old issuer key (`nfltr org move finish`; the fenced log and the root stay, and neither serves) |
| LoseHost | a host's disk is gone, at any point |
| Crash | the new host crashes before it imports; its receive key is a 0600 file and survives |
| Take | a fleet verifier takes a CRL the relay delivers, a newer Number only (`Enrol.tla` Take) |
| Revive | a restore from a backup (MaxRevive > 0, `OrgMoveRestore.cfg`; nfltr's `nfltr-backup.sh restore-secrets`, then `org-issuer.sh restored send` (`nfltr org move send --restored`: `orgissuer.Restore`, `orgpki.Issuer.Restore`) and the move's receive, nfltr `docs/decisions/backup-secrets-2026-11-19.md` "The issuer from a backup"): with the organisation lost (no host holds it, no fenced bundle still importable) a backup copy of any age takes the newest published CRL (the `restored` log line: its Number resumed, its serials listed in every CRL until they expire, the copy's tokens void), then is fenced for a host's receive key and imported there, in one step (the copy is aside and never serves) |

LoseBundle, Import and Take range over a variable (`bundles`, `pub`), so
TLC's coverage lists them as `Next`'s disjuncts at their lines.

## `OrgHolds.tla`: the relay's holds across a move

The issuer writes the organisation's shared mailboxes (`root`, `crl`,
`answers`, a broadcast each; `enrol`, a drop box), each held by one relay
machine (the relay's shared mailboxes, relay-server `spec/Reach.tla`).
`OrgHolds.tla` checks that the hold follows the fence: `nfltr org move
send` releases (relay-server `spec/Reach.tla` GiveUp) only after the fence
and once no issuer service runs (it takes the serve lock), and the new
machine's holder declaration takes the vacant hold; a move back's receive
takes a bundle that extends the fenced log even while the moved keys are
there. Hosts A (first), B (moved to), X (another machine of the account,
which may take a vacant hold once and is revoked by the owner).

| property | means | mutant that breaks it |
|---|---|---|
| HolderKeeps (action) | a serving issuer's hold is neither taken nor vacated by another machine | `handover-to-anyone` |
| OldCannotWrite | once its send ran, the old machine holds nothing | `old-keeps-writing`, `release-without-fence` |
| FinishAfterPublish | finish deletes the moved keys only after the other machine published | `finish-early` |
| RootReadable | the root box is never a drop box: the issuer's read-back before a publish is a member's, so on a fresh relay it makes the broadcast members read (relay-server `spec/Reach.tla` KindOf) | `holder-read` (relay org v0.1.3 to v0.1.6: no machine could join an organisation made on a fresh relay) |
| MoveCompletes (LiveSpec) | a bundle in flight ends with its machine serving, holding the box and publishing (or moving it on) | `old-keeps-writing`, `release-without-fence`, `refuse-own-tombstone`, `refuse-finished-tombstone` (the VM wrapper's receive before) |

| Action | code |
|---|---|
| SvcStart, SvcRead, SvcWrite, SvcStop | `orgenrol.Service.Run`: the serve lock, `maintain` (read under the directory's lock, refused after the fence), `publish` (holder declaration), the return on `ErrMoved` |
| Fence | `orgissuer.Send` (under the directory's lock) |
| Lock, Release | nfltr's `orgcli` `moveSend`: the serve lock (`orgenrol.HoldServeLock`), then `orgenrol.ReleaseHolds` (the `release` declaration) and the bundle |
| Import | `orgissuer.Import` / `placeMembers`: a fenced tombstone the bundle's log extends is replaced, its keys deleted; a finished one's issuer files are set aside (the root file and the machine's own membership `machine/` stay); the VM's `deploy/standalone/org-issuer-remote.sh` `receive` lets both through (refuses only an organisation served there) |
| Finish | nfltr's `orgcli` `moveFinish` (the relay's CRL past the fence's) |
| XTake, Revoke | another machine's holder declaration on a vacant hold; the relay's release of a revoked holder |
| EarlyRelease, XRelease | mutants only (`release-without-fence`, `handover-to-anyone`); coverage skips them |

`OrgHolds.cfg` (a fresh relay or a published root; a move, a move back and a move onto the finished tombstone, X once): 385 states;
`OrgHoldsLive.cfg` the same under LiveSpec. Mutants in `holds-mutants.txt`;
witnesses `WitnessMoved`, `WitnessMovedBack`, `WitnessBackUnpublished`,
`WitnessTakenVacant`, `WitnessLateWrite`, `WitnessFinished`, `WitnessReturnToFinished`, `WitnessReadFirst`. Not traced
yet (gap: the holds are relay state; the move's own recorder covers the
fence, send and import).

## `OrgHosted.tla`: the opt-in hosted issuer (verifier side and the root's CRL of issuers built, lane ORGH1; the hosting itself is design)

The design is nfltr's `docs/decisions/org-hosted-issuer-2026-11-16.md`.
The owner keeps the root and the recovery key; the issuer key moves onto a
machine the hosting service runs (and back) by the fenced move above, and
the root renews it monthly (at most `DelegLife`). k1 is the organisation's
issuer key; k2 a standby the root pre-certified on the hosted machine (the
shape a high-availability design would use), served only by the owner's
signed activation. The attacker owns the relay (it withholds the root's
revocation as long as it likes) and may compromise the hosted machine (it
then holds every key there, a copy that outlives a move off). The
transfer's secrecy, the attested receive key, the root-signed move order
and the operator's commands are `spec/proverif/orghosted.pv`.

| property | means | mutant that breaks it |
|---|---|---|
| AtMostOneIssuer | at most one issuer serves | `auto-takeover` (the hosted side activates the standby because it no longer hears the owner's issuer) |
| ServingAuthorized | an issuer serves only where the owner put it: genesis, a fence naming that host, a signed activation | `auto-takeover` |
| DelegationBound | no session under an issuer key outlives the NotAfter the root signed for it, whoever holds the key | `self-renew` (the hosted issuer extends its own certificate), `until-leaf-only` (a session's admission ends at the leaf's NotAfter alone: a stolen issuer key signs a leaf that outlives it; relay client `orgid` `Checked.Until` today, finding F1 of the design doc) |
| RevokedIssuerRefused | a verifier that took the root's revocation of an issuer admits nothing under it and holds no session under it | `ignore-root-crl`, `keep-sessions` (taken, sessions not cut), `sign-forgets` (the root's machine does not keep a certificate it signed for a remote renewal, `nfltr org issuer sign`, so its revocation does not list it: lane ORGH1R) |
| RootCRLCurrent | the root's CRL of issuers, once signed, outlives every delegation it does not revoke: it is re-signed with each renewal to the new delegation's end, so a machine past its NextUpdate holds no issuer certificate that counts (F1's Until refuses there); its revocations never lapse | `no-resign` (a renewal leaves the CRL of issuers as it was) |
| RevokeTakesEffect (LiveSpec) | a revocation the root signed reaches the verifier once the relay carries it | `no-push` |

Witnesses (each must be violated, the state reachable): `WitnessHostedServes`,
`WitnessMovedOff` (back on the owner's machine while the attacker still
holds a copy taken on the hosted machine), `WitnessStolenSession` (the
bound is a bound, not a prevention: a stolen key admits until its
delegation ends), `WitnessRevokedCut` (a stolen key revoked before its
NotAfter), `WitnessOwnerActivated`, `WitnessRenewed`,
`WitnessRevokedRemoteRenewal` (a revocation listing a certificate a
remote renewal signed), `WitnessResigned` (the CRL of issuers re-signed
at a renewal after a revocation). TLC also showed
that a compromise of the hosted machine yields the standby k2 too
(`until-leaf-only` is caught through k2 at depth 4): a pre-certified
standby is a live credential for its whole life, served or not.

| Action | design |
|---|---|
| Tick | time; a session ends at its admission's Until |
| Renew | the monthly renewal: the serving issuer's request, the root's answer (`org/orgpki/renew.go`); only the root extends a delegation; the root's machine keeps the certificate it signs (`org/orgissuer/store.go` KeepSigned) and re-signs its CRL of issuers, if it has one, into the answer (`IssuerRenewal.Issuers`) |
| SelfRenew | mutant only (`self-renew`); coverage skips it |
| Admit | a verifier admits a machine certificate under k: the chain at now (the issuer's NotAfter), the root's revocations it took; an honest issuer caps the leaf at its own NotAfter (`org/orgpki/profile.go`), a stolen key signs any; the admission ends at the chain's earliest NotAfter |
| Compromise | the hosted machine is compromised: every key there is the attacker's |
| RevokeIssuer | the owner's root signs its CRL of issuers listing every certificate of k it kept |
| Deliver | the relay carries that CRL to a verifier (a running one, or a machine joining: `org/orgenrol/machine.go` trust), which cuts the sessions under the certificates it lists |
| Fence, Import | the fenced move (`OrgMove.tla`): onto the hosted machine to a receive key the hosting service attested, off it by the root's signed order |
| LoseSelf | the owner's machine and its issuer are lost (no move under way) |
| Partition | the hosted side stops or starts hearing the owner's machine |
| OwnerActivate | the owner's signed activation of the standby, only when no issuer serves |
| AutoActivate | mutant only (`auto-takeover`); coverage skips it |

`OrgHosted.cfg` (MaxTime 4, DelegLife 2, CertLife 2): 86240 states, about
19 s under load; `OrgHostedLive.cfg` RevokeTakesEffect under LiveSpec, about 40 s; every
line of `hosted-mutants.txt`, the witnesses and `-coverage 1`:
`scripts/spec-orgmove.sh hosted`, in `ci` (about 40 s more).

| assumption | relied on by | source |
|---|---|---|
| verifiers check the chain at admission with the issuer's NotAfter (x509 Verify), end it at the chain's earliest NotAfter, and take the root's CRL of issuers by a higher Number only | Admit, Deliver | relay `client/orgid/verify.go` (`check`'s Until, `TakeIssuerCRL`; lane ORGH1, bindings `hosted.until`, `hosted.rootcrl`) |
| the root signs a renewal only for the issuer key it pins | Renew | `spec/proverif/orgmove.pv` 5-7 |
| the hosted machine holds no root key and no recovery key | Compromise | `spec/proverif/orghosted.pv` 2, 3 |
| the relay may withhold the root's CRL indefinitely; liveness assumes it carries it in the end | Deliver, RevokeTakesEffect | the threat model |

## Running

`scripts/spec-orgmove.sh ci` (`make spec-orgmove-ci`, in `make ci`, about a
minute; with the trace fixtures): `OrgMove.cfg` (three hosts, one token, one name, one move, four
ordinary acts, two CRLs, one lost bundle, one backup, one lost host, one
crash: 600264 states), `OrgMoveLive.cfg` (MoveCompletes under LiveSpec, no
host lost: 98436 states), every line of `mutants.txt`, every witness, and
`-coverage 1` (fails on an action never taken). `scripts/spec-orgmove.sh
repeat` (`make spec-orgmove-repeat`, not in ci): two moves in a
row, `OrgMoveRepeat.cfg` (5478532 states, about a minute).
`scripts/spec-orgmove.sh holds` (also in `ci`, seconds): `OrgHolds.tla`'s
two configs, its mutants, witnesses and coverage.
`scripts/spec-orgmove.sh restore` (also in `ci`, about 40 s): `OrgMoveRestore.cfg`
(316367 states), `restore-mutants.txt`, its witnesses, `-coverage 1` (Crash
aside: none there; `OrgMove.cfg`'s coverage skips Revive, MaxRevive 0).

## Environment assumptions

| assumption | relied on by | source |
|---|---|---|
| the receive key reaches the old host out of band, intact; the relay never carries it there | Send, Import | `spec/proverif/orgmove.pv` (mutant `recipient-via-relay`) |
| a bundle opens only with its receive key, and the new host checks the log's issuer chains to the pinned root | Import | `spec/proverif/orgmove.pv` (mutants `plain-bundle`, `no-root-check`) |
| the issuer directory's lock orders every act and the fence (`orgissuer.Lock`); the log is synced before an act takes effect (`Store.Sink`) | Fence, the acts | `org/orgissuer/store.go` |
| the old host is honest when it fences: a copy of its keys taken before (a disk image, malware) is a stolen issuer, bounded by the issuer certificate's 30 days | OldCannotIssue | the threat model: an issuer key is a key the owner protects |
| the move completes within the fresh CRL's life (1 h), or the fleet fails closed until it does | MoveCompletes (untimed here) | the design: a move is the owner at both machines |
| a shared mailbox's hold is decided by the mailbox service in one statement per touch; a release vacates only the caller's own hold; its kind (broadcast or drop box) is set by its first declared touch and never changes | OrgHolds SvcRead, SvcWrite, Release, XTake | relay-server `spec/Reach.tla` (GiveUp, ReleaseOnlyOwn), `internal/application/mailbox/scope.go` |
| a running issuer service holds the serve lock (`flock`) for as long as it may publish; the lock is released when its process ends | OrgHolds Lock | `orgenrol/issuer.go` (`Run`), `org/internal/orgfiles` |
| a restore runs only with the organisation lost: the old host deleted, no move under way, and the published CRL lapsed (no issuer signed for its hour; `orgpki.Issuer.Restore` refuses a CRL not lapsed) | Revive (Lost) | nfltr `deploy/standalone/org-issuer-remote.sh` (`restored check`), its runbook "The organisation issuer from a backup" |
| the CRL a restore takes is the newest the fleet holds: the relay's `crl` broadcast keeps the newest publish, and the restore verifies it under the issuer's own key (`orgpki.Issuer.Restore`: no relay's forged CRL); a relay that withholds the newest one is a relay attack outside this model (members would refuse the restored issuer's lower Numbers and fail closed when theirs lapses) | Revive (NewestRev, MaxPub) | `orgenrol.PublishedRevocationList`, relay client `orgid` (`CRLMailbox`) |
| the owner revokes a machine that takes a vacant hold (denial of service is outside the threat model) | OrgHolds Revoke (fair) | the mailbox service: a vacant hold is taken by the first holder declaration |

## Traces

`org/orgpki` records every commit of an issuer when built
`-tags enroltrace` with `ORGMOVETRACE=<dir>` (`trace_on.go`; `trace.go` is
the no-op of every other build): `act` (an ordinary act: its line's hash,
the hash before it, a CRL's Number), `fence` (the moved line, its receive
key) and, from `orgissuer`, `import` (the arrived line, once `Import` has
written its log: an import refused after its arrival committed in memory,
as a move back whose bundle does not continue the tombstone, lands
nothing and is no import; recorded at the commit it read as a second
issuer, 2026-11-15) and `send` (the fenced head sealed to a receive key). `TraceOrgMove.tla` reads them in
order and keeps the properties one process can see: one history (no two
lines after the same one: AtMostOneIssuer, AuditContinuous), nothing after
a fence but its arrival (OldCannotIssue), an import and a send only of a
fence naming their key (ImportFenced: import-unfenced,
fence-names-no-recipient), CRL Numbers that only grow (CRLMonotone). A
`restored` act (a restore from a backup, `orgpki.Issuer.Restore`, its
`num` the published CRL's Number) continues an older line, the lost
machine's: it is no fork, but its Number is at least every one before it
(`restore-behind`, CRLMonotone), and a second line after the same parent
once restored is a fork again.
`scripts/spec-orgmove.sh traces` (`make spec-orgmove-traces`) runs every
test of orgpki, orgissuer and orgenrol that way and checks each
trace (55 traces, 313 lines: 260 act, 22 fence, 14 import, 17 send), then
the fixtures `traces/<Invariant>-*.ndjson`, each of which its invariant
must reject (also in `ci`).

The Go mutants of the same failures (`make test-go-mutants`): orgpki
`serve-after-fence`, `fence-names-no-recipient`, `act-after-fence-verifies`,
`import-unfenced`; orgissuer `no-fence`, `no-spool-in-bundle`,
`reusable-receive-key`, `ephemeral-receive-key`, `no-resend`,
`fence-names-no-recipient`, `no-root-check`, `import-unfenced`, and the
root's of `orgmove.pv` (`root-moves`, `finish-deletes-root`,
`root-left-behind-on-return`), and `receive-drops-membership` (the
receive sets aside only the issuer's files: the receiving machine's own
membership `machine/` stays; member state is not in the model, which
abstracts a host to its issuer directory); orgenrol
`serve-after-fence`; orgpki's restore (`restore.go`, OrgMove.tla Revive):
`number-not-above-published`, `merge-skipped`, `revive-keeps-tokens`,
`restore-not-lapsed`, `restore-any-issuer`, `restore-older-than-copy`,
`adopt-any-signer`, `adopt-unknown-name`, `adopt-without-restore`. The transfer's bindings (`BIND:move.*` of
`spec/proverif/orgmove.pv`) are orgissuer's `TestOrgMoveModelBindings`
(`make spec-bindings`).

`OrgHosted.tla`'s verifier side has its own trace check,
`TraceOrgHosted.tla`, over the lines relay client `orgid`'s verifier
writes under `ENROLTRACE` (the files `spec/enrol/TraceEnrol.tla` checks
too): `itake` (the root's CRL of issuers taken, or refused: a replay, or
`why` `sig`, not the root's), `rotate`, and `check`, whose `is`, `ie` and
`u` are the issuer certificate's serial and NotAfter and the admission's
Until. It keeps DelegationBound (`u` at most the leaf's and the issuer's
NotAfter: `until-leaf-only`), RevokedIssuerRefused (no admission through an
issuer certificate a taken CRL of issuers lists: `ignore-root-crl`) and
Conforms (a CRL of issuers taken by a higher Number only).
`scripts/spec-orgmove.sh htraces` (in `traces`) runs every test of
`client/orgid`, `org/orgmachine` and `org/orgenrol` that way and checks
each trace that holds an `itake` or a `check`, then the fixtures
`traces/hosted/<Invariant>-*.ndjson` (also in `ci`). The time steps of
OrgHosted.tla (Tick) and its hosted-side actions (Fence, Import,
Compromise, OwnerActivate) have no line: nothing in the code does them
yet (the hosting lanes H2, H3).

## Code map

| spec | code |
|---|---|
| OrgMove.tla | org/orgpki/move.go |
| OrgMove.tla | org/orgpki/audit.go |
| OrgMove.tla | org/orgpki/restore.go |
| OrgMove.tla | org/orgissuer/bundle.go |
| OrgMove.tla | org/orgenrol/issuer.go |
| TraceOrgMove.tla | org/orgpki/trace_on.go |
| OrgHolds.tla | org/orgenrol/issuer.go |
| OrgHolds.tla | org/orgenrol/orgenrol.go |
| OrgHolds.tla | org/orgissuer/bundle.go |
| OrgHosted.tla | client/orgid/verify.go |
| OrgHosted.tla | org/orgpki/profile.go |
| OrgHosted.tla | org/orgpki/renew.go |
| OrgHosted.tla | org/orgpki/issuercrl.go |
| OrgHosted.tla | org/orgenrol/issuer.go |
| OrgHosted.tla | org/orgenrol/machine.go |
| OrgHosted.tla | org/orgissuer/store.go |
| TraceOrgHosted.tla | client/orgid/verify.go |
