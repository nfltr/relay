# The root-held member log (lane ROOTHELD, 2026-11-28, design)

nfltr `docs/decisions/root-held-membership-2026-11-28.md`. Every fact that
admits a machine key (which key is which machine of which person, in which
groups) is an entry of an append-only, hash-chained log signed by the root
or by an admin key the root delegated in the log; the issuer only orders
and carries the log and attests freshness (CRL, status) for keys already
in it. `MemberLog.tla` checks that the attacker, owning the relay AND the
issuer, can withhold and deny but never admit. Its message-level half
(signatures, the grant's approval, secrecy) is `spec/proverif/rootheld.pv`.

A design: no code yet, so no trace recorder. Lane RH1 (`org/orglog`) adds
the recorder (`-tags relaytrace`), `TraceMemberLog.tla` and
`scripts/spec-rootheld.sh traces` with the code, and extends the spec with
`rotate`, invites and add codes first.

## Actions (`MemberLog.tla`)

| Action | who | design (the code lane names the Go) |
|---|---|---|
| `Delegate(a)`, `Undelegate(a)` | the root | `delegate`, `undelegate` entries |
| `Append1(i)` | an honest signer's entry the honest issuer sequenced on its head (the step `Delegate` .. `Remove` take) | the compare-and-set append |
| `Add(s, k)`, `Remove(s, k)` | the root or a delegated admin, on the head it holds | `machine-add`, `machine-remove` |
| `StaleSign(s, k, n)` | an honest signer whose copy is stale (the R85PREP stale-head case) signs on an old prefix; the honest issuer's compare-and-set refuses it, the entry exists | the issuer's refusal and the signer's re-sign |
| `Steal(a)` | the attacker takes an admin key | - |
| `Forge(p, o, k, b)` | the attacker signs with the issuer key or a stolen key on any prefix (a fork or a later entry) | - |
| `Deliver(v, e)` | the relay hands a verifier any entry, any order, or none | the log mailbox, the status copy |
| `Sync(v)` | an honest carrier (a session with a member holding the log: head exchange) gives a verifier the whole log | the head exchange in member sessions |

The verifier's copy is the chain its fork choice picks from the valid
entries it holds (on one prefix the root's entry beats an admin's, then the
lowest entry id); an addition admits only from that chain; a removal or an
undelegation takes effect from any valid entry seen, on any branch.

## Invariants and mutants

| property | means | mutant (`mutants.txt`) |
|---|---|---|
| `AdmitOnlyLogged` | an admitted key has an add entry signed by the root, or by an admin delegated (not undelegated) on that entry's own prefix | `issuer-member` |
| `RevokedDelegateRefused` | no entry of an undelegated admin in a verifier's chain past its undelegation, nor outside the prefix of an undelegation it saw | `undelegate-ignored`, `revoke-not-retroactive` |
| `NoForkAccepted` | what a verifier admits comes from one chain of valid entries it holds | `admit-from-seen` |
| `Converge` | verifiers holding the same entries choose the same chain | `first-seen` (`MemberLogTwo.cfg`) |
| `RemovalTakesEffect` (liveness, `LiveSpec`: weak fairness on `Sync`) | a removal in the log ends the key at every verifier | `rm-in-copy-only` |

Witnesses (each violated): `W_AdminAdmits`, `W_RevokedForkRefused`,
`W_ForkSeen`, `W_IssuerRefused`, `W_RemovedOffChain`.
`MemberLog.cfg` (one machine key, one admin, one verifier, chains of
three, one forged entry): 15,660 states, every invariant, every mutant but
`first-seen` caught, every witness reached, `-coverage 1` every action but
`Sync` (a `Deliver` of the canonical head, apart only for its fairness);
`MemberLogLive.cfg`: `RemovalTakesEffect`; `MemberLogTwo.cfg` (two
verifiers): `first-seen` caught by `Converge`, and nightly the whole
check (156,906 states, 2 to 4 minutes on the Mac). `scripts/spec-rootheld.sh ci`
(`make spec-rootheld-ci`, in `make ci`, about 30 s).

## Environment assumptions

| assumption | relied on by | source |
|---|---|---|
| signatures are unforgeable; only a key's holder signs with it | `Forge` signs only with the issuer key and stolen keys | `spec/proverif/rootheld.pv` |
| SHA-256 is collision resistant: an entry id binds its whole prefix | entries are `<<prefix, item>>` | FIPS 180-4 |
| the honest issuer appends only on its head (compare-and-set) | `Append1`, `StaleSign` | the design, section 3 |
| every member session carries both ends' heads end to end | `Sync` and its fairness | the design, section 2; `spec/proverif/e2ee_tcp.pv` (the session is the members') |

## Code map

| spec | code |
|---|---|
| MemberLog.tla | none yet (design: build lanes RH1-RH3 of the decision doc add the member log, its verifier in the client and the issuer as sequencer; each adds its package here) |
