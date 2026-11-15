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
| Fence | `nfltr org move send`, first half: under the lock, the fence line naming the receive key (after a fresh CRL: the move then has the CRL's hour) |
| Send | ... second half: the fenced log and the keys sealed (`crypto/hpke`) to that key, through the relay mailbox `org.<org>.move` or to a file; again until the new host serves |
| Backup | a copy that is not a move: a backup, a disk image, a bundle made before the fence |
| LoseBundle | the relay loses or withholds a bundle (bounded by MaxLostB) |
| Import | `nfltr org move receive`: opens a bundle sealed to its receive key, imports it only when the log ends in the fence naming that key, deletes the receive key as the arrival line commits, serves |
| Wipe | the owner, after `nfltr org status` on the new host shows it serving, deletes the old issuer key (`nfltr org move finish`; the fenced log and the root stay, and neither serves) |
| LoseHost | a host's disk is gone, at any point |
| Crash | the new host crashes before it imports; its receive key is a 0600 file and survives |
| Take | a fleet verifier takes a CRL the relay delivers, a newer Number only (`Enrol.tla` Take) |

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

`OrgHolds.cfg` (a move, a move back and a move onto the finished tombstone, X once): 293 states;
`OrgHoldsLive.cfg` the same under LiveSpec. Mutants in `holds-mutants.txt`;
witnesses `WitnessMoved`, `WitnessMovedBack`, `WitnessBackUnpublished`,
`WitnessTakenVacant`, `WitnessLateWrite`, `WitnessFinished`, `WitnessReturnToFinished`. Not traced
yet (gap: the holds are relay state; the move's own recorder covers the
fence, send and import).

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

## Environment assumptions

| assumption | relied on by | source |
|---|---|---|
| the receive key reaches the old host out of band, intact; the relay never carries it there | Send, Import | `spec/proverif/orgmove.pv` (mutant `recipient-via-relay`) |
| a bundle opens only with its receive key, and the new host checks the log's issuer chains to the pinned root | Import | `spec/proverif/orgmove.pv` (mutants `plain-bundle`, `no-root-check`) |
| the issuer directory's lock orders every act and the fence (`orgissuer.Lock`); the log is synced before an act takes effect (`Store.Sink`) | Fence, the acts | `org/orgissuer/store.go` |
| the old host is honest when it fences: a copy of its keys taken before (a disk image, malware) is a stolen issuer, bounded by the issuer certificate's 30 days | OldCannotIssue | the threat model: an issuer key is a key the owner protects |
| the move completes within the fresh CRL's life (1 h), or the fleet fails closed until it does | MoveCompletes (untimed here) | the design: a move is the owner at both machines |
| a shared mailbox's hold is decided by the mailbox service in one statement per touch; a release vacates only the caller's own hold | OrgHolds SvcWrite, Release, XTake | relay-server `spec/Reach.tla` (GiveUp, ReleaseOnlyOwn), `internal/application/mailbox/scope.go` |
| a running issuer service holds the serve lock (`flock`) for as long as it may publish; the lock is released when its process ends | OrgHolds Lock | `orgenrol/issuer.go` (`Run`), `org/internal/orgfiles` |
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
fence-names-no-recipient), CRL Numbers that only grow (CRLMonotone).
`scripts/spec-orgmove.sh traces` (`make spec-orgmove-traces`) runs every
test of orgpki, orgissuer and orgenrol that way and checks each
trace (66 traces, 387 lines: 320 act, 27 fence, 18 import, 22 send), then
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
`serve-after-fence`. The transfer's bindings (`BIND:move.*` of
`spec/proverif/orgmove.pv`) are orgissuer's `TestOrgMoveModelBindings`
(`make spec-bindings`).

## Code map

| spec | code |
|---|---|
| OrgMove.tla | org/orgpki/move.go |
| OrgMove.tla | org/orgpki/audit.go |
| OrgMove.tla | org/orgissuer/bundle.go |
| OrgMove.tla | org/orgenrol/issuer.go |
| TraceOrgMove.tla | org/orgpki/trace_on.go |
| OrgHolds.tla | org/orgenrol/issuer.go |
| OrgHolds.tla | org/orgissuer/bundle.go |
