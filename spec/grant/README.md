# Time-limited, approved access to a service, in TLA+ (2026-11-25)

Designed in nfltr `docs/decisions/service-access-2026-11-25.md` (lane
SERVICEACCESS), built in lane SA4 (code map below). A principal (a person's device or a machine) asks
for one service for a duration; an approver signs the request; the
organisation's issuer checks the approver's authority (the root-signed
policy) and that the approver is not the requester, and signs one grant
per request. The client presents the grant inside the session's
end-to-end TLS; the serving agent admits only the grant's principal and
service, before its `until`, while the grant is not on the issuer's
revocation list and that list is fresh (younger than `CrlLife`). The
agent's timer ends a session at `until`; a newer list naming the grant
ends it on arrival; a list grown stale ends every grant session. An
approver may instead deny a request: its final answer, after which no
approval the relay replays grants it (`Deny`, `DenyFinal`; lead decision
2026-11-26).

The attacker owns the relay: it replays every approval, withholds or
delays every list and offers the agent any grant. Who can forge or widen
a grant or an app's identity is `spec/proverif/svc_access.pv`; the
principals' certificates (revoke, offboard) are `spec/enrol/` and the
people lane's; a session needs those valid too, which only narrows it.

`make spec-grant-ci` (`scripts/spec-grant.sh ci`): check, the liveness
config, every mutant, every witness, `-coverage 1` and the rejected trace
fixtures. `scripts/spec-grant.sh traces` (in `make spec-traces`): the
tests' traces.

## Invariants and properties

| property | means | mutants that break it |
|---|---|---|
| GrantedOnly | every open session is its grant's principal and service | `agent-any-principal`, `agent-any-service` |
| ExpiryBound | no session is open at or past its grant's `until` | `agent-no-expiry-check`, `expiry-refuses-only` (the timer refuses new sessions, keeps open ones) |
| RevokeBound | a revoked grant's sessions end within `CrlLife` of the revoke, whatever the relay withholds | `agent-no-rev-check`, `revoke-refuses-only`, `stale-list-admits`, `stale-list-keeps` |
| ApprovalOnce | an approval yields at most one grant: a replay neither doubles nor extends access | `issuer-no-replay-set` |
| DenyFinal | a request an approver denied (`nfltr access deny`, the request's final answer) is never granted, whatever approval the relay replays | `issuer-signs-denied` |
| GrantMatchesApproval | every grant is exactly the request (principal, service, duration) an authorised approver other than the requester signed | `issuer-any-approver`, `self-approve`, `dur-from-request` |
| SessionsEnd (liveness, `GrantLive.cfg`, fair clock) | every grant session ends by the agent's timer, not the client | `expiry-refuses-only` |

Witnesses (each must be violated): `WitnessOpened`,
`WitnessExpiredClosed`, `WitnessRevokedClosed`, `WitnessStaleClosed`,
`WitnessTwoGrants` (two grants for one principal and service: an
extension is a new request), `WitnessDenied`.

## Environment assumptions

| assumption | source |
|---|---|
| the agent's clock is the issuer's within the skew the organisation certificates already assume; the model has one clock, so a real bound is `until + skew` | RFC 5280 4.1.2.5 (validity), `spec/enrol/Enrol.tla` |
| the issuer's journal of granted request ids survives its restart (it is the issuer's log, `org audit`) | `org/orgissuer` journal; nfltr `docs/decisions/org-enrolment-2026-11-09.md` |
| the revocation list is the issuer's signed CRL, numbered; the agent takes only a newer one | RFC 5280 5.2.3 (CRL number), `spec/enrol/CrlCarriers.tla` |
| the relay may withhold, delay or replay any message; it cannot forge a signature | `spec/proverif/svc_access.pv` |

## Traces

The issuer (`org/orgpki/grant.go`, `issuer.go`: `grantLine`) and the
serving agent's check (`client/orgid/grant.go`: `grantTrace`) write one
JSON line per step with `-tags enroltrace` and `GRANTTRACE=<dir>`, into
one file per test process: `req`, `sign`, `deny`, `revoke` (an approver's
or the holder's, and every grant a removal of its person or machine
revoked), `crl` (the grant serials it lists) and `admit` (the agent's
check: the grant, the client's principal and services, the CRL it holds,
the admission's end, which is the session's timer). Each writer writes
under its lock, one write a line, so the file is in the order the steps
happened in the test. `TraceGrant.tla` reads them in order, keyed by
organisation, and checks each against Grant.tla's rules given the lines
before it; a step a model mutant names is reported by that mutant's
property (`GrantedOnly`, `ExpiryBound`, `RevokeBound`, `ApprovalOnce`,
`GrantMatchesApproval`, `DenyFinal`), any other by `Conforms`.
`scripts/spec-grant.sh traces` runs every test of `org/orgpki` and
`org/orgenrol` so (77 traces, 2026-11-26: events 24 admit, 143 crl, 2
deny, 12 req, 2 revoke, 10 sign; every kind taken) and then the fixtures:
`traces/<Invariant>-*.ndjson`, one wrong step each, rejected by that
invariant (13 fixtures, every invariant and `Conforms`).

## Code map

| spec | code |
|---|---|
| Request, Sign, Deny, Revoke, Publish | org/orgpki/grant.go, org/orgpki/issuer.go (`CRL`, the removal's `revokeOf`), org/orgpki/status.go |
| Open, Tick, Deliver (the agent) | client/orgid/grant.go (`CheckGrant`, `AdmitClient`, `ClientCertificate`), client/orgid/identity.go (`Hold`), client/agent/org.go (`holdAdmission`), org/orgmachine/orgmachine.go (`CheckClient`) |
| the acts over the relay | org/orgenrol/order.go (`SendGrant`), org/orgenrol/issuer.go (`decide`) |
| TraceGrant.tla | org/orgpki/trace_on.go, client/orgid/trace_on.go |

Go mutants (`org/orgpki/testdata/mutants.txt`, the Grant.tla mutant each
is named after where it has one): `issuer-no-replay-set`,
`issuer-any-approver`, `self-approve`, `dur-from-request`,
`approval-any-body`, `revoke-not-listed`, `removal-keeps-grants`,
`revoke-by-anyone`, `grant-any-signer`, `grant-any-holder`,
`grant-any-service`, `grant-no-expiry-check`, `grant-no-rev-check`,
`grant-stale-list-admits`, `grant-until-uncapped`, `grant-as-machine`;
`client/orgid/testdata/mutants.txt`: `client-no-grant`.
