# The people layer in TLA+ (2026-11-25; the code: org/orgpki people.go, lane PEOPLE2)

A person (someone who signs in with the organisation's OIDC provider)
joins through an invite, owns machines, has a role (owner, admin,
member) and is offboarded in one act that ends every credential of every
machine they own; one machine's revoke (a lost laptop) ends every
credential of that machine the same way (lane ONEREVOKE). Authority stays with the organisation: the owner is the
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
delivers it in seconds), relay-server's `MachineAuth.tla` (the relay
credential's revoke) and relay-server's `PersonEnrol.tla` (the relay
applying the issuer's signed status: here `Applies` and `RelayCut`). Groups are the certificate's
(lane ONEGROUP mirrors the signed map to the relay): a revoked machine
leaves every group, so groups add no state here.

## Invariants

| property | means | mutant that breaks it |
|---|---|---|
| AuthorizedActs | every act in the log was one its actor's role allowed: the owner anything, an admin invites and offboards members only | `admin-invites-admin`, `admin-changes-role`, `admin-offboards-admin` |
| AdminsByOwner | every admin was made one by an owner's invite or role change | `role-from-request` (the join takes the role from the request), `role-unlogged` |
| JoinNeedsInvite | no person without an open invite: a sign-in alone enrols no one | `idp-alone-enrols` |
| NoOrphan | a machine of a removed person holds no live credential (certificate, relay credential, address) | `offboard-misses-machine`, `code-outlives-offboard` (a machine code made before the offboard redeemed after it) |
| ReachBound | Bound after an offboard or a machine's revoke: no session of the machine, its relay credential revoked, its addresses ended | `relay-not-filed`, `no-fail-closed` (a verifier keeps admitting on a lapsed CRL), `relay-persons-only` (the relay applies only removed persons' person rows: a code's machine, or one machine revoked, keeps its relay credential; the relay before lane ONEREVOKE), `relay-ids-only` (a joined device revoked alone is missed), `revoke-no-cut` (the credential deleted, the open link left: its sessions and addresses stay) |
| RevokedNoLive | a revoked machine's certificate and relay credential are both ended in the one act | `revoke-relay-only` (`nfltr machines revoke` before lane ONEREVOKE: the account machine deleted, the organisation certificate live) |
| NoGrantOfRemoved | no grant in force is held or was approved by a removed person | `removal-keeps-grants`, `removal-keeps-approvals` |
| AuditComplete | the log names every join, machine, offboard and role | `offboard-unlogged` |
| OwnerStays | the owner is never offboarded (the owner leaves by moving the root: `spec/orgmove`) | none: no action removes the owner |
| RemovedStaysOut (action property) | a removed person stays removed: coming back is a new invite, a new person | `rejoin-old-invite` |

Witnesses (each must be violated, the state reachable): `WitnessJoined`,
`WitnessAdminActs`, `WitnessSecondMachine`, `WitnessRoleChanged`,
`WitnessWindow` (the residual the bound states: a removed person's
session still open before the CRL reaches its verifier),
`WitnessOffboardReached`, `WitnessLostLaptop` (one machine of a person
still in the organisation revoked at the relay, its address ended),
`WitnessGranted`. `-coverage 1` shows every action taken.

Results (2026-11-28, lane ONEREVOKE, `People.cfg`: owner and two people,
two machines, MaxTime 2, Bound 1): 211,326 distinct states, every
invariant holds; all 18 mutants caught; all 8 witnesses reached; every
action taken. (2026-11-25: 245,346 states, 12 mutants, before the relay's
apply, the one-machine revoke and the grants were modelled.)

## Actions (`People.tla`)

| action | who |
|---|---|
| Invite | an owner (any role) or an admin (member) invites a new person |
| Join | the person's device signs in and proves the invite: a person with the invite's role, its first machine |
| Mint, Redeem | a person makes a machine code; a new machine redeems it (the issuer checks the person's status when it answers) |
| Serve, Open | a machine serves an nf1 address through the relay; a verifier admits a session of a machine |
| Approve | an approver grants a holder access (Grant.tla, abstracted to the pair) |
| ChangeRole | the owner (the root's approval) makes a member an admin or back |
| Offboard | an owner or admin: the person removed, every machine's certificate listed and revoked in the status, the relay applying it (`RelayCut`), their grants held and approved revoked, one log line |
| RevokeOne | the owner revokes one machine (`nfltr machines revoke` on the issuer's machine): its certificate listed and revoked in the status, the relay applying it |
| RelayCut (in Offboard, RevokeOne) | the relay applies the status: the credential revoked, the machine's link cut (its sessions through the relay and the addresses it served end) |
| Reach | the CRL push reaches the verifiers (a session over a direct path ends here or at Tick) |
| Tick | time passes; a verifier whose CRL lapsed refuses (fail closed) |

## Environment assumptions

| assumption | source |
|---|---|
| the issuer's log is a single writer: an offboard and a redemption are ordered | org/orgissuer (one log, one lock); `spec/orgmove/OrgHolds.tla` |
| a verifier ends a session by the CRL's NextUpdate when no newer CRL arrives (fail closed) | `spec/enrol/Enrol.tla` RevocationBound, RFC 5280 §5.1.2.5 |
| the issuer serves (`nfltr org serve`): it puts its signed status at once on a change (the directory's notice), and the relay carries each put to the accounts service as it keeps it, so the relay's apply happens within the bound; the apply itself is code (relay-server `PersonEnrol.tla`), modelled in `RelayCut` | `org/orgenrol` `watchDir`, `putStatus`; relay-server `org_status_people.go`; `spec/enrol/RevokePush.tla` |
| the relay routes an nf1 open only to a live agent record; a revoked machine's cut ends its record, so the addresses it served end with it | relay-core `core/directory` (the nf1 index pruned with the record); nfltr `docs/decisions/nf1-rendezvous-2026-11-13.md` |
| the IdP authenticates; its compromise is `people.pv`'s | OpenID Connect Core 1.0 |
| a bearer address copied to a third party, or its key copied to a machine outside the organisation, is out of scope: nothing ends a copy (the offboard says so) | `cap_address.pv` |

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
| People.tla Offboard (the grants) | org/orgpki/grant.go (`revokeOf`, `revokeApprovedBy`), org/orgpki/issuer.go (the removal's replay) |
