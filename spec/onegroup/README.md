# One set of groups: the issuer's half (lane ONEGROUP-C1, 2026-11-27)

nfltr `docs/decisions/one-group-2026-11-25.md`. With an organisation, the
issuer's signed member map is the only source of a machine's groups; the
relay mirrors it (relay-server `spec/GroupMirror.tla`, which models this
layer only by the guarantees below) and the peers check the member
certificate's OU. This module checks the issuer itself (`org/orgpki`):

- a member's groups change only by the root's signed move order
  (`orgpki.MoveOrder`, `Order.Act` `move`; `spec/proverif/orggroup.pv`
  query 5, `BIND:group.movesig`), applied once (a replay moves nothing
  back), into groups within the issuer's bound;
- the move revokes every certificate of the member issued so far: the next
  CRL lists them until they expire, and the status is signed only after
  that CRL (`ErrCRLDue`), so no status shows a move whose old certificates
  its CRL does not list (GroupMirror.tla `Move`, `Sign`: "the status and
  the CRL signed together");
- every certificate issued after the move (the keeper's renewal, which a
  moved certificate may still ask and asks at once, `orgmachine`
  `RenewDue`; a rebind token's enrolment) carries the new groups.

The put to the relay (`orgenrol` `putStatus`: on change, every
`copyEvery`, and at once after a failed read of the requests, GroupMirror.tla
`Reput`) and the relay's copy are GroupMirror.tla's. Abstracted: time and
lifetimes (an expired certificate leaves the CRL and serves no session:
`spec/enrol/Enrol.tla`); one organisation; the signatures (an order is in
`orders` only when the root signed it).

## Actions and the Go they model (`GroupIssuer.tla`)

| Action | Go |
|---|---|
| `Ask(m, k, gs)` | the root signs a move order for the status's serial (`orgpki.MoveOrder`; nfltr `nfltr org approve` of a move wish) |
| `Apply(m, k, gs)` | `Issuer.ApplyOrder` of a move (`applyMove`): one `regrouped` log line |
| `Renew(m, k)` | `Issuer.Renew`, a rebind token's `Enrol` (`rebind`): `issueEntry` with the name's groups now |
| `CRL` | `Issuer.CRL`: the serials a move revoked (`nameRec.moved`) |
| `Sign` | `Issuer.SignedStatus`, refused while a move waits for its CRL (`moveDue`) |

## Invariants and mutants

| property | means | mutant (TLA+ and Go, `org/orgpki/testdata/mutants.txt`) |
|---|---|---|
| `MovedOnlyAsked` | a member's groups in a status change only by a root-signed order | `move-without-order` |
| `AppliedOnce` | an order is applied at most once | `move-replayed` |
| `InBound` | a status places members only in groups of the issuer's bound | `move-outside-bound` |
| `StatusWithItsCRL` | each status's CRL lists every certificate of a member in other groups than the status's | `move-keeps-old-cert`, `status-before-crl`, `renew-old-groups` (Go: `rebind-token-groups`, `move-keeps-groups`) |

Witnesses (each violated): `W_Moved`, `W_RenewedInto` (a certificate in
the new groups after a move), `W_MovedBack` (two moves), `W_WishRefused`
(the relay's unsigned wishes exist, a move applied, none of them).
`GroupIssuer.cfg` (one member, two groups and one outside the bound, two
certificates, two CRLs, two statuses): 4340 states, 4 s, every invariant,
every mutant caught, every witness reached, `-coverage 1` every action
(`scripts/spec-onegroup.sh ci`, `make spec-onegroup-ci`, in `make ci`).

## Environment assumptions

| assumption | relied on by | source |
|---|---|---|
| the root's signature is unforgeable and only the owner's approval makes one | `Ask`, `MovedOnlyAsked` | `spec/proverif/orggroup.pv` queries 5, 7 |
| the issuer applies acts one at a time, each logged before it takes effect | every action | `Issuer.commit` (one lock), `spec/orgmove/OrgMove.tla` |
| a peer refuses a serial its CRL lists and a lapsed CRL | `StatusWithItsCRL` means a session refused | `client/orgid` `Verifier.Check`, `spec/enrol/Enrol.tla` |

## Code map

| spec | code |
|---|---|
| Ask, Apply | org/orgpki/order.go (`MoveOrder`, `ApplyOrder`, `applyMove`), org/orgenrol/issuer.go (`decide`), org/orgenrol/order.go (`SendOrder`) |
| Renew, CRL, Sign | org/orgpki/issuer.go (`apply` regrouped, `rebind`, `CRL`), org/orgpki/status.go (`SignedStatus`), org/orgmachine/orgmachine.go (`RenewDue`) |
| TraceGroupIssuer.tla | org/orgpki/trace_on.go (`groupLine`, `groupStatusLine`) |

## Traces

With `-tags enroltrace` and `GROUPTRACE=<dir>` the issuer writes one JSON
line per step under its lock (`issue`, `move`, `crl`, `sign`);
`TraceGroupIssuer.tla` reads each test's lines in order and checks
`IssueInMap`, `AppliedOnce`, `CRLListsMoved` and `StatusWithItsCRL` as far
as they show them (a step that maps to no action fails `Conforms`).
`scripts/spec-onegroup.sh traces` runs every test of `org/orgpki` and
`org/orgenrol` (nightly, `make spec-traces`); `mtraces` the move tests
alone (seconds, in `ci`). Each `traces/<Invariant>-*.ndjson` is a mutant's
trace its invariant rejects (`fixtures`).
