# Organisation certificates' lifecycle in TLA+ (2026-11-09)

An organisation root
certifies an issuer; the issuer gives each machine a short-lived x509
certificate and renews it; the owner revokes a machine through a signed
CRL that the relay carries (and may replay or withhold); after the root's
primary key is stolen the owner rotates with the recovery key. A verifier
(a client dialing a machine by name, or a service admitting a group)
admits a session while the certificate has not expired, chains to the
root it trusts, and its CRL is current (NextUpdate not passed) and does
not list its serial (the issuer lists every unexpired serial of a revoked
name); it ends sessions at the certificate's
NotAfter, at the CRL's NextUpdate (fail closed), and on each CRL and
rotation it takes. `Enrol.tla` is the design, checked before any code.
Enrolment itself (single-use tokens, names, chains, groups, the recovery
signature) is the symbolic model `spec/proverif/enrol.pv`; this model
starts with the machines enrolled. The join by token over the relay's
mailboxes (a lost or late answer, the join run again, the root it takes
after a rotation) is `Join.tla`.

## Invariants and properties

| property | means | mutant that breaks it |
|---|---|---|
| RevocationBound | CrlLife after a revoke no verifier holds a session of the machine, whatever CRLs the relay delivered | `fail-open` (admit and keep sessions on a lapsed CRL) |
| RevokedMachineRefused | once a verifier took a CRL naming a machine, it holds no session of that machine again, under any serial | `no-crl-check`, `no-cut-on-update`, `accept-older-crl` (a replayed older CRL), `revoke-current-only` (the CRL lists the newest serial only, the one before it is still valid after a renewal), `renew-revoked` |
| NoExpiredSession | no session outlives its certificate | `no-expiry-check`, `no-expiry-timer` |
| NoRenewAfterRevoke | the issuer never certifies a machine after its revoke | `renew-revoked`, `check-at-request` (the issuer decides by the state when the request was posted: a revoke while it sat in the mailbox is missed) |
| ForgedOnlyUnderStolenRoot | a certificate the attacker holds exists only under a root it stole: the issuer renews only serials its own log holds | `renew-forged` |
| MachineHoldsItsKey | a machine with no request outstanding holds a certificate of the key it made last | `install-stale-answer` (the machine installs an answer for an older key: one the relay kept or replayed) |
| SessionsOnTrustedRoot | every session is under the root its verifier trusts; a rotation ends the stolen root's sessions | `keep-old-root` |
| RootsAreOwners | a verifier trusts only roots the owner made (a rotation needs the recovery key) | `rotate-by-primary` |
| RebindBound | CrlLife after a rebind no verifier holds a session of a serial it retired (the old machine id's certificates), whatever CRLs the relay delivered | `rebind-keeps-serials` (the rebind's CRL lists none of the name's earlier serials) |
| RetiredRefused | once a verifier took the rebind's CRL, it holds no session of a retired serial | `rebind-keeps-serials` |
| NoRenewOfRetired | the issuer renews no serial a rebind retired (the old disk's renewal request, still in the relay's mailbox) | `renew-rebound` |
| NoRenewPastGrace | the issuer renews a certificate after its NotAfter only within RenewGrace of it (`orgpki.RenewGrace`, 90 days since lane SEAMLESS) | `renew-past-grace` |
| MoveOnlyByKey (Rebind.cfg) | a name moves to a new relay machine id without the owner's token only on its own current key's request (the id under the key's signature: `enrol.pv` query 20) | `move-no-key` |
| MoveOnlyOwnAccount (Rebind.cfg) | ... and only to a machine of the issuer's own relay account by that name: another account's machine never takes the name's membership | `move-any-account` |
| GraceOnlyNewest | ... and only the name's newest serial (a superseded one's key is retired: `enrol.pv` 2) | `grace-any-serial` (EnrolLoss.cfg: the answer the machine never installed is newer) |
| RenewsAfterExpiry (LiveSpec) | a machine whose certificate expired while the issuer was out of reach renews once it answers, without a restart (or the grace ended, it was revoked, or an answer it never installed superseded it) | `no-renew-after-expiry` (the design before 2026-11-20: the issuer refused every expired certificate, so an outage through the last third of the lifetime needed a new enrolment, nfltr `docs/decisions/org-renew-after-outage-2026-11-20.md`) |
| TakesEffect (LiveSpec) | every revoke reaches every verifier | `push-only` (no backstop read: a lost push is never made good) |
| MachinesFollowRotation (LiveSpec) | every machine still enrolled moves to the new root (or its certificate lapses visibly) | `no-reissue-on-rotation` (renewal by time only), `no-retry` (a machine whose request or answer the relay lost never asks again) |

Witnesses (each must be violated, the state reachable): `WitnessRenewed`,
`WitnessRenewedAfterExpiry` (a renewal from a certificate past its NotAfter),
`WitnessRevokeSeen`, `WitnessFailClosed` (a verifier whose CRL lapsed),
`WitnessForgedSession` (before the rotation reaches it, a verifier does
admit a certificate forged under the stolen root: the bound the design
states, not a property it claims), `WitnessRotated`,
`WitnessSessionAfterRotation`, `WitnessRetried` (a machine asks again with a new key after a loss),
`WitnessRebound`, `WitnessSessionAfterRebind` (the new machine id's
certificate admitted), `WitnessRetiredHeld` (before the rebind's CRL
reaches it, a verifier does hold a session of a retired serial: the bound
RebindBound states), `WitnessMoved` (a name moved on its key's request).

## `Enrol.tla`

| Action | design (phase 2 code) |
|---|---|
| Tick | time passes; each verifier's timer ends sessions at the certificate's NotAfter and at its CRL's NextUpdate |
| Admit | a peer presents a certificate (honest, a stolen machine's, or forged); TLS VerifyConnection: chain, name, NotAfter, CRL |
| Request | the machine (`orgenrol.Keeper`) is due (half its lifetime, up to 10 % later (lane SEAMLESS), or at once after a rotation; its certificate valid or within RenewGrace after its NotAfter), makes a new key and posts a renewal signed by the current one to `org.<org>.enrol`; with an earlier request or answer lost (none pending for its newest key) it asks again with another key |
| Issue | the issuer (`nfltr org serve`, `orgenrol.Service`) reads a request and decides under its lock as of now: it refuses a revoked name, a certificate expired RenewGrace ago and an expired one that is not the name's newest serial (`orgpki.RenewGrace`), renews only a serial its own log holds, and posts the answer to `org.<org>.answers` under the request's id |
| IssueForged | mutant `renew-forged` only: the issuer renews a forged certificate the attacker presents |
| Install | the machine installs an answer for the key it made last (`orgmachine.Install`: any other is refused) |
| Lose | the relay loses a request or an answer (bounded by MaxLost) |
| Revoke | `nfltr org revoke <name>`: one CRL listing every unexpired serial of the name |
| Rebind | `nfltr org token --rebind <name> --machine-id <new>` redeemed by the new machine (`orgpki.Enrol` of a rebind token: one `rebound` log entry certifying it and retiring the name's earlier serials, nfltr `docs/decisions/org-rebind-2026-11-17.md`); the CRL signed then lists them; `Renew` refuses a retired serial. Its authority (only the operator's token, only its name) is `enrol.pv` query 11 |
| Move | lane SEAMLESS (nfltr `docs/decisions/seamless-certificates-2026-11-20.md`): the keeper (`orgenrol.Keeper`, `RelayMachineID`) finds the relay machine id changed (`nfltr config login` again) and sends a renewal naming the new id under its key's signature (`orgpki.NewMoveRequest`); `orgpki.Issuer.Renew` asks its `MovePolicy` (nfltr: the id is the issuer's own account's machine of that name, `machines resolve`) and applies the `rebound` log entry, as Rebind |
| Rebound | the effect Rebind and Move share (one `rebound` log entry: the name's new machine id, its earlier serials retired, `orgpki.Issuer` `rebind`), not a step of its own |
| Republish | the issuer re-signs the CRL before its NextUpdate |
| Take | a verifier takes a newer CRL and re-checks its sessions |
| Replay | the relay delivers an older CRL |
| Fetch | the newest CRL reaches a verifier: the push, or the verifier's backstop read before NextUpdate |
| Steal | the attacker takes the current root's primary key |
| Forge | ... and mints a certificate under it for any name |
| Rotate | `nfltr org rotate`: a new primary, cross-signed by the recovery key |
| EvilRotate | mutant `rotate-by-primary` only: the stolen primary signs a rotation |
| TakeRoot | a verifier takes the rotation statement and ends sessions under any other root |

## `Join.tla`

A machine's `nfltr org join` posts a request binding a key to the token
(`orgenrol.Join`), the issuer answers it under its lock when it reads it
(`orgpki.Issuer.Enrol`), and the join installs the answer or gives up
waiting; run again with the token, it asks with the key it kept
(`orgenrol.JoinKeyFile`), under a request id of its own run (the relay
keeps a sender's idempotency key a day, an answer an hour), and takes the
answer to its run's or to its first run's request. One token, one name;
the relay loses one request or answer; one rotation.

| property | means | mutant that breaks it |
|---|---|---|
| RefusedOnlyForCause | a join is refused only when another key redeemed the token or the name was revoked, and a root only when the owner did not make it: a lost or late answer never burns the name, a rotation never strands a join | `burn-name` (the issuer refuses a redeemed token's own key), `new-key-per-join` (each run a new key): together the code before 2026-11-15; `pin-root-only` (only the pinned root, not one its recovery key certifies) |
| OneKeyPerToken | every certificate a token gets is for one key | `reissue-any-key` |
| NoIssueAfterRevoke | nothing is issued under a token after the name's revoke | `reissue-revoked` |
| NoRetiredKeyRevived | a key a renewal retired is never certified by the token again | `reissue-after-renewal` |
| JoinRootsAreOwners | a machine joins only under a root the owner made | `any-root` |
| RefusedOnlyForCause (relabel) | ... or the relay changed the request's relay machine id or named another sender (it can refuse a join, as it can by not carrying it) | |
| BindOnlyStated | a certificate binds a relay machine id only as the token's holder stated it under the token's MAC (`orgpki.EnrolRequest` MachineID, MachineMAC; BIND:enrol.id): the relay cannot choose it | `bind-unmacd` (the id the MAC does not cover, such as the sender the relay names, bound) |
| BindOnlyOwnAccount | ... and only the issuer's account machine of the name (the move policy, as Enrol.tla Move) | `bind-any-account` |
| JoinedBound | a join the relay did not tamper with installs a certificate naming its relay machine id, so the keeper of its first `nfltr cat serve` moves nothing (lane LOGINREDS: that move replaced the pair while a second serve read it) | `bind-none` (the code before: a login bundle's certificate named no id) |

Witnesses: `WitnessRetriedJoin`, `WitnessReissued`,
`WitnessJoinedAfterLoss`, `WitnessJoinedAfterRotation`,
`WitnessRefusedOther`, `WitnessRefusedEvil`, `WitnessJoinedBound`,
`WitnessRefusedRelabeled`.

| Action | code |
|---|---|
| Start | `orgenrol.Join`: the root message checked (`trust`: the pinned root, or one the pinned recovery key certifies), the token's kept key, the request posted under the run's id, stating the machine's relay machine id under the token's MAC (`Pins.MachineID`, `orgpki.NewEnrolRequestFor`) |
| Issue | `orgpki.Issuer.Enrol` (through `orgenrol.Service`): a redeemed token answers again only its key, while the name is not revoked and its newest certificate is the token's; a token naming no relay machine id binds the request's when its MAC holds and the move policy admits it; `orgenrol.Service` refuses a request whose id is not its sender's |
| Relabel | the relay changes a request's relay machine id (the MAC no longer holds: `orgpki.Issuer.Enrol` refuses) or names another sender (`orgenrol.Service.wrongMachine` refuses) |
| Install | `orgenrol.Join`: the answer to this run's or the first run's request, checked by `orgmachine.Checked` (key, chain) |
| GiveUp | the join's `--wait` ends |
| Lose | the relay loses a request or an answer (or keeps it past its TTL) |
| Other | the token leaked: another key's request |
| Renew, ReplayOld | a renewal retires the join key; the attacker posts it with the token |
| Revoke, Rotate | `nfltr org revoke`, `nfltr org rotate` |
| InstallForged | mutant `any-root` only: the attacker's answer under its own root |

The join takes the first answer it reads: after a rotation between a
run's answer and the next run, the first run's answer (under the old
root) fails the chain check until the relay drops it (an hour); the model
lets the join skip it (a liveness gap, no safety one).

## `RevokePush.tla`

How fast a revoke reaches the revoked machine's peers, and what bounds it
when an event is lost (2026-11-16, lane ORGREVPUSH; before, the issuer
published a CRL another process wrote only at its next round,
`serveWait` 10 s, most of the measured ~9 s cut). `nfltr org revoke`
writes the CRL into the issuer's directory; the file-change notice of
that write ends the issuer service's round, which reads the directory and
publishes the CRL; the append wakes every peer's parked long-poll (the
push), and each peer cuts its sessions of the machine. Every step is an
event, modelled as happening before time passes (the network's latency).
Each may be lost; each has a backstop: the service's round (`ServeWait`),
the peer's fresh read (`FollowEvery`). A relay withholding the backstop
reads too is `Enrol.tla`'s `RevocationBound` (NextUpdate, fail closed).
One revoked machine; its peers (a client and an agent: both ends, either
path, `DirectPath.tla`'s reset) are the verifiers.

| property | means | mutant that breaks it |
|---|---|---|
| EventBound | with no notice and no push lost, every session of the machine ends before time passes | `poll-only` (no notice: the code before 2026-11-16), `clear-wake-after-publish` (a notice that comes during a maintain is dropped with the round's end) |
| BackstopBound | with any losses, every session ends within ServeWait + FollowEvery | `no-serve-backstop` (a lost notice, no round), `no-follow-backstop` (a lost push, no fresh read) |
| NoAdmitAfterLearn | a peer that took the CRL holds no session of the machine: none admitted after, the held one cut | `admit-after-crl`, `no-cut` |

Witnesses: `WitnessCutByPush`, `WitnessServeBackstop` (a lost notice,
published by the round), `WitnessFollowBackstop` (a lost push, cut by the
fresh read), `WitnessHeldAfterRevoke` (the bound's window: admitted after
the revoke, before the peer learned it).

| Action | code |
|---|---|
| Revoke | `orgissuer.RevokeMachines` (and nfltr's `org revoke`, any writer of `crl.der` or `audit.jsonl`): the write is the notice (`orgenrol.watchDir`, fsnotify on the issuer directory) |
| LoseWake | no watcher (`watchDir` failed: no inotify or kqueue left), a missed event |
| Read | `orgenrol.Service.Run`: the notice cancels the round's long-poll (one buffered value: taken before the next `maintain` reads) |
| Publish | `service.maintain`: the CRL appended under its replace key |
| Deliver, LosePush | the relay's mailbox wakes the parked pull (`follow`, `orgid.Follow`), or loses it |
| FreshRead | `follow`'s read from 0 every `FollowEvery` |
| Admit, Take | the peer's TLS check and `Hold` / `holdAdmission` on its CRL change |
| Tick | time passes once nothing is in flight and no backstop is overdue |

`RevokePush.cfg`: two peers, MaxTime 6, ServeWait 2, FollowEvery 2, two
losses (50100 states, seconds); in `ci`, `check`, `coverage`.

Library (owner's library-first rule): the notice is
`github.com/fsnotify/fsnotify` v1.9.0 (BSD-3-Clause, inotify, kqueue,
ReadDirectoryChangesW; its one dependency `golang.org/x/sys` is in the
module already; nfltr links it already). Looked at: the revoke command
signalling the issuer over a socket of its own (every writer would have
to call it: a rotation, the account-revocation tie-in, nfltr's own
copies), and a stat poll (a poll). The watcher covers every writer.

## `CrlCarriers.tla`

The CRL off the mailbox (2026-11-20, lane MAILBOXSPOF, nfltr
`docs/decisions/crl-off-mailbox-2026-11-20.md`; the 2026-11-19 mailbox
outage lapsed every member's CRL after an hour). The issuer publishes
each CRL on two carriers that fail apart: the mailbox
(`orgid.CRLMailbox`, the push) and the relay's own copy (relay-server
`/api/v1/org-crl/<org id>`, kept in the relay's process: a restart loses
it, and the issuer puts it again every CopyEvery). A member reads the
copy every FollowEvery besides the push, and takes either through the one
rule (`orgid.Verifier.TakeCRL`: signed under the trusted root, newer than
the CRL held, NextUpdate not passed). The relay may withhold, replay or
make up either carrier's CRL. CrlLife stays one hour: it is Enrol.tla's
RevocationBound. The relay's alert (`nfltr_relay_org_crl_copies`
`freshness="late"`) is the copy past its re-sign time: the issuer stopped
re-signing or stopped reaching the relay. Time passes only once the
issuer's due re-sign and put, the mailbox's push and the member's due
read are done (as RevokePush.tla); a read due at a put's instant comes
after it (the bound's margin covers the other order).

| property | means | mutant that breaks it |
|---|---|---|
| RevocationBound | CrlLife after the revoke no session of the machine, whatever either carrier delivered | `stale-copy` (the copy's CRL valid for CrlLife from its read, not to its NextUpdate: a stale CRL accepted) |
| RevokedMachineRefused | once the verifier took a CRL listing the machine, no session of it | `copy-rollback` (an older CRL taken from the copy: the revoked machine admitted again by the second path), `copy-unsigned` (a CRL the relay made, taken from the copy) |
| NoSessionOnLapsed | no session on a CRL past its NextUpdate | (the take rule's NextUpdate check; Enrol.tla `fail-open`) |
| NoRenewAfterRevoke | the issuer renews nothing after the revoke: its own log decides, never a carrier's CRL | `renew-by-copy` (a renewal decided by the copy's CRL, which can predate the revoke) |
| CurrentWithoutMailbox | with the issuer up longer than CopyEvery + FollowEvery the verifier holds a current CRL, mailbox up or not | `mailbox-only` (the design before 2026-11-20: the mailbox the only carrier) |
| AlertOnlyOnIssuer | the alert fires only while the issuer is down (or back and not yet put): never for a mailbox outage | `alert-on-mailbox` |
| AlertBeforeLapse | the alert fires by the time a replica's copy lapses | `alert-on-mailbox` |
| CurrentWithoutMailbox, AlertOnlyOnIssuer (two replicas) | a put on one replica reaches every replica: a member reading any of them holds a current CRL, and no replica's copy goes late while the issuer is up | `one-replica` (the put kept only by the replica it landed on: the design before MAILBOXSPOF2) |
| AlertOnlyOnIssuer (two replicas) | a delivery older than a put the replica took directly meanwhile is not kept | `deliver-lww` (last writer wins: two puts landing on different replicas, the bus's older one replaced the newer and the replica served a stale copy) |
| AlertWhileIssuerDown | with the issuer down past its last put's re-sign time the alert fires (Vanish after the last restart at the latest), whichever replicas restarted | `alert-forgets` (no memory of a copy a restart lost: a restart during an issuer outage silenced the alert, the design before MAILBOXSPOF2) |

Witnesses: `WitnessLapsed` (an issuer outage lapses the CRL: the bound
is fail closed), `WitnessCopyWhileMailboxDown` (a CRL taken from the
copy while the mailbox is down), `WitnessAlert`, `WitnessLearned`,
`WitnessRestartWhileIssuerDown` (a relay restart during an issuer outage
leaves no copy), `WitnessAlertWithoutCopy` (the alert fires with no copy
anywhere: the monitoring's memory), `WitnessPeerCopy`
(`CrlCarriersReplicas.cfg`: a member takes a CRL from a replica the put
did not land on).

Replicas (lane MAILBOXSPOF2): a put lands on one replica, which keeps it
and publishes it on the replicas' bus (relay-server's Redis pub/sub, as
its revocations); every other replica keeps it on delivery (Deliver,
before time passes) unless it holds a newer copy (by the CRL's
ThisUpdate). A read lands on any replica. A restart loses the
replica's copy and what the bus sent it meanwhile (a resubscribe is
modelled as a restart). The alert is per replica: its copy late
(`OrgIssuerUnreachable`), or a copy a restart lost and no put brought
back for Vanish (`OrgCRLCopyVanished`, nfltr `deploy/metrics/alerts.yml`:
the count of copies below its maximum of the last day; an issuer that is
up puts again within CopyEvery < Vanish).

| Action | code |
|---|---|
| Republish, Revoke | `orgenrol.service.maintain` (`orgpki.Issuer.CRL`), `nfltr org revoke` |
| Publish | `service.publish` to `orgid.CRLMailbox` |
| PutCopy | `service.putCopy`: `mailboxclient.Client.PutOrgCRL` when the CRL changed or `copyEvery` passed; relay-server `orgCRLCopies.serve` keeps it and publishes it to the peer replicas |
| Deliver | relay-server `runOrgCRLCopies`: a peer replica keeps a put the bus delivered |
| Renew | `orgpki.Issuer.Renew` (Enrol.tla Issue) |
| IssuerDown/Back, MailboxDown/Back, RelayRestart | outages: the issuer's process, the mailbox service, a relay replica's process (its copy is in memory) |
| Push | `orgid.Follow`'s long-poll of the mailbox |
| ReadCopy | `orgid.Follow`'s read of the copy every `FollowEvery` (`mailboxclient.Client.OrgCRL`) |
| Replay, ServeForged | the relay serving an older CRL, or one it made (refused: `copy-unsigned` takes it) |
| Admit | the verifier's TLS check (`orgid.Identity.CheckServer` and siblings) |
| Tick | time passes once nothing due is left; sessions end at the CRL's NextUpdate |

`CrlCarriers.cfg`: MaxTime 7, CrlLife 5, ReSign 3, CopyEvery 1,
FollowEvery 1 (the code's 60, 20, 5 and 10 minutes: CopyEvery +
FollowEvery < ReSign), Vanish 2 (10 minutes), one replica, one outage of
each kind (1.76M states, 20 s; in `ci`); `CrlCarriersReplicas.cfg`: the
same on two replicas (15M states, under its replica symmetry about
half; `check` and nightly, `make spec-traces` running `spec-enrol.sh
replicas`: its mutants and witness in `ci`); both in `coverage` (`make
spec-enrol-coverage`). The CrlCarriers
trace check (`TraceCrlCarriers.tla`, "Traces") runs in `traces`.

## Running

`scripts/spec-enrol.sh ci` (`make spec-enrol-ci`, in `make ci`):
`Enrol.cfg` (one machine, one verifier, MaxTime 4, CertLife 3, CrlLife 2,
two root generations, MaxKeys 4, no losses: 280785 states), `EnrolLive.cfg`
(the same under LiveSpec), `EnrolLoss.cfg` (the relay loses one request or
answer, no forgeries, LiveSpec and every invariant: 162030 states;
`no-retry` and `WitnessRetried` run on its constants), `Rebind.cfg`
(Enrol.cfg with one rebind and no forgeries: 150556 states; the rebind's
mutants and witnesses run on its constants), `Join.cfg`
(Join.tla, every invariant: 7475 states), every line of
`mutants.txt`, every witness, and the trace fixtures. Losses are a config
of their own because they multiply Enrol.cfg's states tenfold (MaxLost 1
there: 1.46M states). `coverage`: `-coverage 1`, fails on an action never
taken (EvilRotate and IssueForged aside, mutant-only steps; Lose in
EnrolLoss.cfg; Rebind in Rebind.cfg; Join.cfg's, InstallForged aside).

## Traces

`org/orgpki` records each step of the issuer, and the
relay client's `orgid` (the verifier, `client/orgid`)
each step of every verifier, when built `-tags enroltrace` with
`ENROLTRACE=<dir>` (`trace_on.go` in each; `trace.go` is the no-op of every
other build): issue, refuse, revoke, crl (the issuer) and take, rotate,
check (a verifier: Take, Fetch and Replay; TakeRoot; Admit and the re-check
of a held session); an enrolment's issue and refusal carry its token and
key, checked by `Join.tla`'s Issue rules (`OneKeyPerToken`,
`NoRetiredKeyRevived`, `RefusedOnlyForCause`, and `NoRenewAfterRevoke`
for a token answered after the revoke). `TraceEnrol.tla` reads
the lines in order and requires each outcome to be the one this model's
rules give from what the lines before it established; a wrong outcome a
model mutant names is reported by that mutant's property. A CRL may also
list an expired serial (no act: a restore from a backup lists the serials
of the CRL it took for MachineLife, `spec/orgmove/OrgMove.tla` Revive). `scripts/spec-enrol.sh
traces` (`make spec-enrol-traces`) runs every test of orgpki, orgmachine and
orgenrol (the mailbox round trips, the push and the backstop, the rotation)
that way and checks each trace (54 traces, 375 lines); with the Go mutant
`renew-revoked` applied (and orgid's `fail-open`, `accept-older-crl` and
`no-expiry-check`; orgpki's `burn-name` and `reissue-any-key`), the trace
check rejects the recorded traces by that mutant's property. `traces/<Invariant>-*.ndjson` are fixtures each rejected by its
named invariant, `traces/Accepted-*.ndjson` fixtures it must accept (a
renewal 30 days after the NotAfter: inside SEAMLESS's 90-day grace)
(`fixtures`, in `ci`). `scripts/check-spec-actions.sh`
fails when a line kind TraceEnrol reads is no longer written by orgpki or
orgid.

Join.tla's machine side is recorded by `org/orgenrol`'s `Join` into the
same `<pid>.ndjson` (`trace_on.go`; one append per line, a run's request
logged before it is posted and its end after its answer was read, so the
issuer's answer falls between them): `jroot` (the root check: `own` when
the root is the owner's, the pinned one or one the pinned recovery key
certifies, decided by the recorder apart from `trust`; `ok` when `trust`
took it), `jstart` (machine directory `m`, token, key, the run's request
id and the first run's) and `jend` (`joined` by answer `id` for key `ak`,
`refused`, `failed`: GiveUp). `TraceJoin.tla` requires a run again to ask
with the key the join keeps for its token (RefusedOnlyForCause, mutant
`new-key-per-join`), a root to be taken exactly when it is the owner's
(RefusedOnlyForCause `pin-root-only`, JoinRootsAreOwners `any-root`), an
install to take this run's or the first run's answer for its key, and
every line to be a step (Conforms); Issue is TraceEnrol's (above).
`traces` checks every trace with join lines and fails when none takes a
root taken, a root refused, a join run again, and each of joined,
refused, failed; `traces/<Invariant>-*.join` are the fixtures each
rejected by its invariant, `Accepted-*.join` accepted. The other actions
are no code's: Lose, Other, ReplayOld and InstallForged are the relay's
or the attacker's, Renew, Revoke and Rotate are TraceEnrol's lines.

CrlCarriers.tla's carrier steps are recorded to `<pid>.crlcarriers` by
`org/orgenrol` (the issuer's `put`, logged before it is sent, and
`publish`; a machine's Keeper's `take`) and relay client `orgid`
(`Follow`'s `take`): a take names its carrier (`via`: `mailbox`, the
push; `copy`, the relay's copy) and its outcome (`res`: taken, same,
refused). `TraceCrlCarriers.tla` requires a CRL taken, whatever carried
it, to be within its NextUpdate (`RevocationBound`, mutant `stale-copy`)
and newer than every CRL the member took of that issuer before
(`RevokedMachineRefused`, `copy-rollback`), a CRL the issuer publishes to
have been put on the copy first (`PutBeforePublish`: a mailbox failure
never holds the copy back), and every line to map to a step (`Known`).
`traces` checks every recorded one (orgpki's, orgmachine's and orgenrol's
tests, and client/orgid's `TestFollow*`) and fails when no trace takes
the issuer's put, its publish, a take by the push, a take by the copy and
a copy refused; `traces/<Invariant>-*.crlcarriers` are the fixtures each
rejected by its invariant.

The issuer service's RevokePush.tla steps are recorded the same way by
`org/orgenrol` (`trace_on.go`: `<pid>.revokepush` beside the other lines):
`notice` (a file-change notice, with the CRL then in the directory),
`read` (maintain's CRL, logged under the directory's lock), `publish`.
`TraceRevokePush.tla` requires a read after a notice to read that write
or a newer one (`ReadSeesNotice`: the notice is logged after its write,
the read under the lock) and the CRL published to be the one the round
read (`PublishesRead`); a line of another kind is `Known`'s. `traces`
checks every recorded one; `traces/<Invariant>-*.revokepush` are the
fixtures each rejected by its invariant.

## Environment assumptions

| assumption | relied on by | source |
|---|---|---|
| a CRL, a rotation statement and a certificate cannot be forged without the key that signs it; the relay may delay, replay or drop them | Replay, Fetch, TakeRoot | `spec/proverif/enrol.pv` |
| a verifier's clock is within the skew the lifetimes allow (minutes against CrlLife = 1 h) | Tick | the design |
| the issuer's log and CRL are written under one lock: a renewal is ordered before or after a revoke | Issue, Revoke | `orgissuer.Lock` |
| the relay may lose, keep or replay a request or an answer but forge neither: requests are signed by the current key or bound to a token, answers are the issuer's certificates for a key the machine checks | Lose, Install | `spec/proverif/enrol.pv`; `orgmachine.Checked` |
| the issuer is out of reach for a while (its mailbox or its process down) and the machine may be off: the model does not force time to pass (Tick is not fair), so RenewsAfterExpiry asks renewal to complete once the issuer answers, not before a deadline | Tick, Request, Issue | nfltr `docs/decisions/org-renew-after-outage-2026-11-20.md` (the 2026-11-19 mailbox outage) |
| a timer may run slower than the wall clock (host sleep): the machine reads the clock again at least every minute | Request | `orgenrol` wakeEvery |
| the relay's copy is in each replica's process: a restart loses it (the issuer puts it again every CopyEvery); the replicas' bus (Redis pub/sub) delivers a put to every subscribed replica within moments and keeps nothing for one that was away | CrlCarriers RelayRestart, Deliver, ReadCopy | nfltr `docs/decisions/crl-off-mailbox-2026-11-20.md`; Redis pub/sub's at-most-once delivery (redis.io "Pub/Sub") |
| the monitoring keeps the copies' count for a day (Prometheus retention well past it) | CrlCarriers Alert (OrgCRLCopyVanished) | nfltr `deploy/metrics/` |
| a machine's Install is one step: its key and certificate are two files replaced write-ahead as one pair (`client/pairfile`: the new key beside the old, the certificate, then the swap; the next writer finishes a stopped swap), and every reader takes the key the certificate certifies (`orgid.ReadPair`; read again, at most 5 s, only while another process replaces the pair) | Install | `spec/pair/MachinePair.tla` (lane CERTATOMIC; before it lane CERTPAIR: nfltr `TestLoginJoinsTheOrganisation`, `nfltr cat serve --ssh` read a renewal's new key with the old certificate); guards `TestEveryStoppedRenewalOpens`, `TestReadPairWaitsForTheWritersCertificate`, mutants `read-pair-once` and `client/pairfile/testdata/mutants.txt` |
| the recovery key is never online with the primary | RootsAreOwners | the design |
| one issuer acts on the log at a time, also across a move to another machine (`nfltr org move`): the old machine acts no more after its fence, the new one continues the same log and CRL Number | Issue, Revoke, Republish | `spec/orgmove/OrgMove.tla` (AtMostOneIssuer, OldCannotIssue, CRLMonotone) |
| the issuer's own certificate is not modelled: a stolen issuer key mints within its NameConstraints and groups until its NotAfter (30 days), a rotation or the root's CRL of issuers, and a session admitted under it ends at that NotAfter at the latest (`orgid` `Checked.Until`, the chain's earliest NotAfter; `spec/orgmove/OrgHosted.tla` DelegationBound and RevokedIssuerRefused) | (stated bound, not a property) | the threat model: an issuer key is a key the owner protects |

## Code map

| spec | code |
|---|---|
| Enrol.tla | org/orgpki/issuer.go |
| Enrol.tla | client/orgid/verify.go |
| Enrol.tla | org/orgenrol/ |
| Enrol.tla | org/orgmachine/orgmachine.go |
| Enrol.tla | org/orgissuer/store.go |
| Join.tla | org/orgpki/issuer.go |
| Join.tla | org/orgenrol/machine.go |
| Join.tla | org/orgenrol/issuer.go |
| RevokePush.tla | org/orgenrol/issuer.go |
| RevokePush.tla | org/orgenrol/orgenrol.go |
| CrlCarriers.tla | client/orgid/follow.go |
| CrlCarriers.tla | client/mailboxclient/orgcrl.go |
| CrlCarriers.tla | org/orgenrol/machine.go |
| CrlCarriers.tla | org/orgenrol/issuer.go |
| TraceEnrol.tla | org/orgpki/trace_on.go |
| TraceEnrol.tla | client/orgid/trace_on.go |
| TraceJoin.tla | org/orgenrol/trace_on.go |
| TraceRevokePush.tla | org/orgenrol/trace_on.go |
| TraceCrlCarriers.tla | org/orgenrol/trace_on.go |
| TraceCrlCarriers.tla | client/orgid/trace_on.go |
