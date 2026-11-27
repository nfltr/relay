# A machine's key and certificate replaced as one pair in TLA+ (2026-11-20)

A machine holds two pairs of files, each a key and the certificate of that
key: the organisation identity (`org/machine/machine.key` +
`machine.pem`, written by `org/orgmachine` on a join and every renewal) and
the relay credential (`machine.key` + `machine.json`, written by nfltr's
`nfltr config login` through `machinecert.SavePair`). Each file is replaced
by one rename, so a writer that died between the key and the certificate
(CERTPAIR's writer: the key, then the certificate) left a key the
certificate does not certify, and the machine needed `nfltr config login` /
`nfltr org join` again. Lane CERTATOMIC makes the replacement write-ahead
(`client/pairfile`, nfltr `docs/decisions/machine-pair-atomic-2026-11-20.md`):
the new key goes beside the old one (`machine.key.next`), then the
certificate, then the new key is renamed over the old; a reader takes
whichever of the two keys the certificate certifies, and the next writer
first finishes a swap its predecessor left (roll forward, as a journal's
recovery does). The layout of an enrolled machine does not change: no
migration, older binaries read the same two files.

`MachinePair.tla` is the design, checked before the code.

## Invariants and properties

| property | means | mutant that breaks it |
|---|---|---|
| Usable | at every step a writer may stop at (crashed, failed, or running), the certificate certifies `machine.key` or `machine.key.next`: a reader always finds a pair, no user action | `key-first` (CERTPAIR's writer), `cert-first` (the certificate before the new key), `no-recovery` (a writer overwrites the `machine.key.next` a crashed one left the certificate's key in), `no-next-read` (the reader ignores `machine.key.next`) |
| ReaderCompletes (LiveSpec) | a reader ends with a pair once writers stop | `key-first`, `no-next-read` |

Witnesses (each must be violated, the state reachable):
`WitnessCrashMidSwap` (a writer stopped between the certificate and the
swap), `WitnessRolledForward` (the next writer finished that swap),
`WitnessReadNext` (a reader took `machine.key.next`), `WitnessReplaced` (a
reader took a replaced pair).

## `MachinePair.tla`

| Action | code (`client/pairfile`) |
|---|---|
| Lock | the pair's writers are serialised: `orgmachine` holds `renew.lock` (`LockRenewal`, taken by `WriteFiles` and every renewal's `Install` caller); `nfltr config login` is one command (environment assumptions) |
| Recover | `Pair.Write`'s first step: when the certificate certifies `machine.key.next` and not `machine.key`, rename the first over the second |
| WriteNext | the new key written aside, fsynced, renamed to `machine.key.next`, the directory fsynced |
| WriteCert | the certificate, the same way, over the old one |
| Swap | `machine.key.next` renamed over `machine.key`, the directory fsynced |
| WriteKey | only under `key-first`: the key over the old one before the certificate |
| Crash | the writer dies or fails after any step; its lock is released |
| RStart, RCert, RNext, RKey, RCheck | `Pair.Read`: the certificate, then `machine.key.next`, then `machine.key`; the first the certificate certifies, else read again (bounded by 5 s, against a writer that keeps replacing) |

`scripts/spec-pair.sh ci` (`make spec-pair-ci`, in make ci, seconds):
both configs, every mutant, the witnesses, -coverage 1 (`WriteKey` is
taken only under its mutant), and the traces.

## Traces

`client/pairfile` built `-tags pairtrace` with `PAIRTRACE=<dir>` writes one
JSON line per step (`trace_on.go`): the step and what the files are after
it (the certificate exists; it certifies the key, the new key; the new key
exists).
`TraceMachinePair.tla` reads a trace in order: each line must be one of the
model's steps from the one before (a lock at any point: the writer before
it stopped), leave the files as that step does, and leave a usable pair
once a certificate exists (the model starts enrolled; a first enrolment
stopped before its certificate leaves the machine not enrolled, and the
join is run again, as before).
`spec-pair.sh traces` runs `client/pairfile`'s tests (every crash point of
`TestEveryCrashLeavesAPair`) that way, then the fixtures: each
`traces/<Invariant>-*.ndjson` must be rejected by its invariant.

## Environment assumptions

| assumption | relied on by | source |
|---|---|---|
| a rename within one directory replaces its target atomically: a reader sees the old file or the new one | every writer step, the reader | POSIX `rename(2)`; Windows `MoveFileEx(MOVEFILE_REPLACE_EXISTING)` (Go `os.Rename`) |
| a process crash (kill -9, panic, a failed step) keeps every rename it made, in order | Crash | POSIX: the renames are done in the kernel before the call returns |
| a power loss keeps a rename only once the file was fsynced before it and the directory after it; the writer does both at each step (the directory fsync is skipped on Windows, where NTFS journals the rename) | Crash after power loss | `fsync(2)`; ext4/APFS ordered metadata; `org/internal/orgfiles` does the same |
| one writer of a pair at a time, released when it dies | Lock | `orgfiles.Lock` (`flock`/`LockFileEx`); `nfltr config login` is not run twice at once on one config directory (residue: two at once may leave the later login's key with the earlier's certificate, as before) |
| a renewal of the relay credential writes only `machine.json`, a certificate of the same key, and only while the directory holds this process's pair (`machinecred` `ownsDir`) | the model has no renewal of it: it changes no version | `client/machinecred/credential.go` `save` (residue, named there: a login between the check and the rename) |
| `NFLTR_MACHINE_KEY` set: the key is not read from the directory, only the certificate | out of the model | `client/machinecred/credential.go` `load` |

## Code map

| spec | code |
|---|---|
| MachinePair.tla | client/pairfile/pairfile.go |
| MachinePair.tla | client/machinecert/files.go |
| MachinePair.tla | client/machinecred/credential.go |
| MachinePair.tla | client/orgid/identity.go |
| MachinePair.tla | org/orgmachine/orgmachine.go |
| TraceMachinePair.tla | client/pairfile/trace_on.go |
