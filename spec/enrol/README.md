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
starts with the machines enrolled.

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
| TakesEffect (LiveSpec) | every revoke reaches every verifier | `push-only` (no backstop read: a lost push is never made good) |
| MachinesFollowRotation (LiveSpec) | every machine still enrolled moves to the new root (or its certificate lapses visibly) | `no-reissue-on-rotation` (renewal by time only), `no-retry` (a machine whose request or answer the relay lost never asks again) |

Witnesses (each must be violated, the state reachable): `WitnessRenewed`,
`WitnessRevokeSeen`, `WitnessFailClosed` (a verifier whose CRL lapsed),
`WitnessForgedSession` (before the rotation reaches it, a verifier does
admit a certificate forged under the stolen root: the bound the design
states, not a property it claims), `WitnessRotated`,
`WitnessSessionAfterRotation`, `WitnessRetried` (a machine asks again with a new key after a loss).

## `Enrol.tla`

| Action | design (phase 2 code) |
|---|---|
| Tick | time passes; each verifier's timer ends sessions at the certificate's NotAfter and at its CRL's NextUpdate |
| Admit | a peer presents a certificate (honest, a stolen machine's, or forged); TLS VerifyConnection: chain, name, NotAfter, CRL |
| Request | the machine (`orgenrol.Keeper`) is due (2/3 of its lifetime, or at once after a rotation), makes a new key and posts a renewal signed by the current one to `org.<org>.enrol`; with an earlier request or answer lost (none pending for its newest key) it asks again with another key |
| Issue | the issuer (`nfltr org serve`, `orgenrol.Service`) reads a request and decides under its lock as of now: it refuses a revoked name and an expired certificate, renews only a serial its own log holds, and posts the answer to `org.<org>.answers` under the request's id |
| IssueForged | mutant `renew-forged` only: the issuer renews a forged certificate the attacker presents |
| Install | the machine installs an answer for the key it made last (`orgmachine.Install`: any other is refused) |
| Lose | the relay loses a request or an answer (bounded by MaxLost) |
| Revoke | `nfltr org revoke <name>`: one CRL listing every unexpired serial of the name |
| Republish | the issuer re-signs the CRL before its NextUpdate |
| Take | a verifier takes a newer CRL and re-checks its sessions |
| Replay | the relay delivers an older CRL |
| Fetch | the newest CRL reaches a verifier: the push, or the verifier's backstop read before NextUpdate |
| Steal | the attacker takes the current root's primary key |
| Forge | ... and mints a certificate under it for any name |
| Rotate | `nfltr org rotate`: a new primary, cross-signed by the recovery key |
| EvilRotate | mutant `rotate-by-primary` only: the stolen primary signs a rotation |
| TakeRoot | a verifier takes the rotation statement and ends sessions under any other root |

## Running

`scripts/spec-enrol.sh ci` (`make spec-enrol-ci`, in `make ci`):
`Enrol.cfg` (one machine, one verifier, MaxTime 4, CertLife 3, CrlLife 2,
two root generations, MaxKeys 4, no losses: 280785 states), `EnrolLive.cfg`
(the same under LiveSpec), `EnrolLoss.cfg` (the relay loses one request or
answer, no forgeries, LiveSpec and every invariant: 162030 states;
`no-retry` and `WitnessRetried` run on its constants), every line of
`mutants.txt`, every witness, and the trace fixtures. Losses are a config
of their own because they multiply Enrol.cfg's states tenfold (MaxLost 1
there: 1.46M states). `coverage`: `-coverage 1`, fails on an action never
taken (EvilRotate and IssueForged aside, mutant-only steps; Lose in
EnrolLoss.cfg).

## Traces

`org/orgpki` records each step of the issuer, and the
relay client's `orgid` (the verifier, `client/orgid`)
each step of every verifier, when built `-tags enroltrace` with
`ENROLTRACE=<dir>` (`trace_on.go` in each; `trace.go` is the no-op of every
other build): issue, refuse, revoke, crl (the issuer) and take, rotate,
check (a verifier: Take, Fetch and Replay; TakeRoot; Admit and the re-check
of a held session). `TraceEnrol.tla` reads
the lines in order and requires each outcome to be the one this model's
rules give from what the lines before it established; a wrong outcome a
model mutant names is reported by that mutant's property. `scripts/spec-enrol.sh
traces` (`make spec-enrol-traces`) runs every test of orgpki, orgmachine and
orgenrol (the mailbox round trips, the push and the backstop, the rotation)
that way and checks each trace (52 traces, 348 lines); with the Go mutant
`renew-revoked` applied (and orgid's `fail-open`, `accept-older-crl` and
`no-expiry-check`), the trace check rejects the recorded traces by that mutant's
property. `traces/<Invariant>-*.ndjson` are fixtures each rejected by its
named invariant (`fixtures`, in `ci`). `scripts/check-spec-actions.sh`
fails when a line kind TraceEnrol reads is no longer written by orgpki or
orgid.

## Environment assumptions

| assumption | relied on by | source |
|---|---|---|
| a CRL, a rotation statement and a certificate cannot be forged without the key that signs it; the relay may delay, replay or drop them | Replay, Fetch, TakeRoot | `spec/proverif/enrol.pv` |
| a verifier's clock is within the skew the lifetimes allow (minutes against CrlLife = 1 h) | Tick | the design |
| the issuer's log and CRL are written under one lock: a renewal is ordered before or after a revoke | Issue, Revoke | `orgissuer.Lock` |
| the relay may lose, keep or replay a request or an answer but forge neither: requests are signed by the current key or bound to a token, answers are the issuer's certificates for a key the machine checks | Lose, Install | `spec/proverif/enrol.pv`; `orgmachine.Checked` |
| the recovery key is never online with the primary | RootsAreOwners | the design |
| one issuer acts on the log at a time, also across a move to another machine (`nfltr org move`): the old machine acts no more after its fence, the new one continues the same log and CRL Number | Issue, Revoke, Republish | `spec/orgmove/OrgMove.tla` (AtMostOneIssuer, OldCannotIssue, CRLMonotone) |
| the issuer's own certificate is not modelled: a stolen issuer key mints within its NameConstraints and groups until its NotAfter (30 days) or a rotation | (stated bound, not a property) | the threat model: an issuer key is a key the owner protects |

## Code map

| spec | code |
|---|---|
| Enrol.tla | org/orgpki/issuer.go |
| Enrol.tla | client/orgid/verify.go |
| Enrol.tla | org/orgenrol/ |
| Enrol.tla | org/orgmachine/orgmachine.go |
| Enrol.tla | org/orgissuer/store.go |
| TraceEnrol.tla | org/orgpki/trace_on.go |
| TraceEnrol.tla | client/orgid/trace_on.go |
