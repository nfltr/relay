# The people layer in TLA+ (2026-11-25; the code: org/orgpki people.go, lane PEOPLE2)

A person (someone who signs in with the organisation's OIDC provider)
joins through an invite, owns machines, has a role (owner, admin,
member) and is offboarded in one act that ends every credential of every
machine they own. Authority stays with the organisation: the owner is the
root holder, an admin is someone the owner's invite or role change made
one, the issuer's log is the roster and the audit. The IdP only
authenticates a sign-in and the relay only carries; who can forge or
replay what is `spec/proverif/people.pv`. The design is nfltr's
`docs/decisions/people-layer-2026-11-25.md`; `People.tla` is that design,
checked before any code (`make spec-people-ci`).

It extends, by their guarantees: `spec/appenrol/AppEnrol.tla` (a person's
sign-in enrolment, `RevokeUser`: here `Join` and the certificate half of
`Offboard`), `spec/enrol/Enrol.tla` (`RevocationBound`: a verifier ends a
revoked machine's sessions by the CRL's NextUpdate, fail closed: here
`Reach` and `Tick`), `spec/enrol/RevokePush.tla` (the push that usually
delivers it in seconds) and relay-server's `MachineAuth.tla` (the relay
credential's revoke: here `RelayRevoke`). Groups are the certificate's
(lane ONEGROUP mirrors the signed map to the relay): a revoked machine
leaves every group, so groups add no state here.

## Invariants

| property | means | mutant that breaks it |
|---|---|---|
| AuthorizedActs | every act in the log was one its actor's role allowed: the owner anything, an admin invites and offboards members only | `admin-invites-admin`, `admin-changes-role`, `admin-offboards-admin` |
| AdminsByOwner | every admin was made one by an owner's invite or role change | `role-from-request` (the join takes the role from the request), `role-unlogged` |
| JoinNeedsInvite | no person without an open invite: a sign-in alone enrols no one | `idp-alone-enrols` |
| NoOrphan | a machine of a removed person holds no live credential (certificate, relay credential, address) | `offboard-misses-machine`, `code-outlives-offboard` (a machine code made before the offboard redeemed after it) |
| ReachBound | Bound after an offboard: no session of the machine, its relay credential revoked, its addresses rotated | `relay-not-filed`, `no-fail-closed` (a verifier keeps admitting on a lapsed CRL) |
| AuditComplete | the log names every join, machine, offboard and role | `offboard-unlogged` |
| OwnerStays | the owner is never offboarded (the owner leaves by moving the root: `spec/orgmove`) | none: no action removes the owner |
| RemovedStaysOut (action property) | a removed person stays removed: coming back is a new invite, a new person | `rejoin-old-invite` |

Witnesses (each must be violated, the state reachable): `WitnessJoined`,
`WitnessAdminActs`, `WitnessSecondMachine`, `WitnessRoleChanged`,
`WitnessWindow` (the residual the bound states: a removed person's
session still open before the CRL reaches its verifier),
`WitnessOffboardReached`. `-coverage 1` shows every action taken.

Results (2026-11-25, `People.cfg`: owner and two people, two machines,
MaxTime 2, Bound 1): 245,346 distinct states, every invariant holds; all
12 mutants caught; all 6 witnesses reached; every action taken.

## Actions (`People.tla`)

| action | who |
|---|---|
| Invite | an owner (any role) or an admin (member) invites a new person |
| Join | the person's device signs in and proves the invite: a person with the invite's role, its first machine |
| Mint, Redeem | a person makes a machine code; a new machine redeems it (the issuer checks the person's status when it answers) |
| Serve, Open | a machine serves an nf1 address; a verifier admits a session of a machine |
| ChangeRole | the owner (the root's approval) makes a member an admin or back |
| Offboard | an owner or admin: the person removed, every machine's certificate listed, its relay revoke and address rotation filed, one log line |
| Reach, RelayRevoke, Rotate | the CRL push reaches the verifiers; the relay applies the revoke; the address rotates |
| Tick | time passes; a verifier whose CRL lapsed refuses (fail closed) |

## Environment assumptions

| assumption | source |
|---|---|
| the issuer's log is a single writer: an offboard and a redemption are ordered | org/orgissuer (one log, one lock); `spec/orgmove/OrgHolds.tla` |
| a verifier ends a session by the CRL's NextUpdate when no newer CRL arrives (fail closed) | `spec/enrol/Enrol.tla` RevocationBound, RFC 5280 §5.1.2.5 |
| an honest relay applies a filed machine revoke within the bound | relay-server `MachineAuth.tla`, `spec/enrol/RevokePush.tla` (30 s push) |
| an nf1 address served by a machine stops when that machine's keeper rotates it or the relay refuses the machine | nfltr `cat serve --new-address`; `cap_address.pv` |
| the IdP authenticates; its compromise is `people.pv`'s | OpenID Connect Core 1.0 |
| a bearer address copied to a third party is out of scope: rotation ends it, nothing ends a copy before | `cap_address.pv` |

## The code (lane PEOPLE2)

`org/orgpki/people.go`: the roster is the issuer's log. An invite line
(`invite`: person, role, the invite's public key as its id, expiry 7
days, the actor and its role), the join (the `issued` line of a sign-in
naming the invite and its role), `role` lines, the removal (a `revoked`
line naming the person, the actor, the person's role and `filed`: each
machine's name and relay machine id, whose relay revoke and address
rotation it files). The owner's acts are the root's signature, an
admin's the key of one of the admin's machines' certificates, its role
read from the log at each request (`ApplyPeople`, carried as
`Request.People`). A sign-in enrols a new key only with an invite
(`SignInRequest.Invite`, `ProveInvite`): the invite is an Ed25519 key's
seed the inviter made, the log holds its public key, the device signs its
two keys with it (people.pv `BIND:people.invite`). The domain rules of
APPID2 (a sign-in rule's email domains enrolling anyone of a domain) are
gone (owner decision 2026-11-25: invites only). Go mutants per model
mutant: `org/orgpki/testdata/mutants.txt` "The people layer" (17; the
unlogged mutants cannot be planted: an act takes effect only by its log
line, `commit`).

## Traces

`scripts/spec-people.sh traces` (in `make spec-traces`, nightly): every
test of `org/orgpki` and `org/orgenrol` built `-tags enroltrace` with
`PEOPLETRACE=<dir>` writes the people lines of each issuer's log as it
commits them (`org/orgpki/trace_on.go` `peopleTrace`: invite, join, add,
role, remove, revoke), each trace checked by `TracePeople.tla`: every
line is one People.tla's rules allow after the lines before it; a wrong
line a model mutant names is reported by that mutant's property, any
other by `Conforms`. A rejected fixture per property in `traces/`
(`<Property>-*.ndjson`, in `make spec-people-ci`).

## Code map

| spec | code |
|---|---|
| People.tla, TracePeople.tla | org/orgpki/people.go, org/orgpki/signin.go, org/orgpki/trace_on.go |
