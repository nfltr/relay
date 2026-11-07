# ProVerif models: A2A end-to-end encryption

Symbolic (Dolev-Yao) models of the A2A E2EE protocol in `client/rpcclient`,
checked with [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/)
2.05 (`make spec-proverif`, in `make ci`). The attacker is every relay and
the link between relays: it reads, drops, reorders, replays and forges any
message, chooses connect labels and routing, and holds the relays' CA. The
crypto is perfect (X25519 as Diffie-Hellman with its one equation, HMAC,
HKDF and the Noise KDF chain as free functions, AES-GCM as an AEAD that
opens only under its key, nonce and AD). Lane A2AID; the design of Part 2
is nfltr's `docs/decisions/a2a-machine-identity-2026-11-07.md`.

ProVerif ships as source only: `scripts/fetch-proverif.sh` builds it once,
with a pinned OCaml 4.14.2 also from source, into `~/.cache/relay-proverif`
(both tarballs pinned by sha256; a C compiler, make and curl; offline after
the first run, about 5 minutes on the Mac). `run.sh [model]` runs each line
of `expect.txt`: `<model> <flags> <results>`, the model with those flags
(a line ending `(* ONLY:f *)` is kept only with flag f, one ending
`(* NOT:f *)` only without it) and its `RESULT` lines in order must read
`<results>`: `T` the query holds, `F` ProVerif found an attack (its trace
is in the log, `PROVERIF_OUT=<dir>` keeps them), `?` not proved. A mutant
is a flag that puts a bug back; its line lists the queries that must then
fail. Other E2EE paths' models (lane E2EEPROOF) use the same layout, script
and pin.

## Environment assumptions

| assumption | source |
|---|---|
| X25519 is a Diffie-Hellman group (CDH hard, small-subgroup keys refused) | RFC 7748; Go `crypto/ecdh` rejects the all-zero shared secret |
| HMAC-SHA256 and HKDF-SHA256 are PRFs; SHA-256 collision resistant | RFC 2104, RFC 5869 |
| AES-256-GCM is an AEAD; random 96-bit nonces do not repeat under one key | NIST SP 800-38D (2^32 messages per key) |
| Noise NKpsk0 / NNpsk0 as specified | Noise Protocol Framework rev. 34, `github.com/flynn/noise` |
| the HMAC input encoding `label 0 txn 0 keys` is injective | the labels are prefix-free; the keys after the second 0 have fixed length (`a2a_e2ee.go` `a2aE2EEPairingTag`) |
| a call's frames reach the other end in order, unless the relay misbehaves | gRPC stream per agent, relay-core sessions (relied on by v2's counters only) |
| the root pairing key and machine keys never pass through a relay | nfltr `a2akeys`: files made on a root holder, copied out of band |

## Models

| file | what |
|---|---|
| `a2a_today.pv` | today: interactive handshake, frames, machine keys, revoke; root holder R on relay X, machines B, E (honest), C (leaked), D (leaked, revoked at phase 1) on relay Y |
| `a2a_today_0rtt.pv` | today: the 0-RTT first flight (Noise NKpsk0 to the label's static key) |
| `a2a_today_unkeyed.pv` | today without a pairing key |
| `a2a_machine.pv` | Part 2, wire v2: Noise NNpsk0 under the owner-derived machine key, key id from the called agent id, prologue binding txn, caller, callee and key id, per-direction counter keys, authenticated end |
| `a2a_machine_0rtt.pv` | Part 2, wire v2: the 0-RTT flight with the same bindings |

Two relays (the owner's 2026-11-07 addition): caller on X, callee on Y,
frames over the link (today the replica link, `relay-server`
`core/replicas`). Flags `honestX`, `honestY` make that relay's hops private
channels with an honest forwarding process (Y routes by agent id, stamps
the source by connection); the link is public in every variant, since a
compromised relay holds its end of it. So the variants are: `-` both
relays (colluding), `honestY` X alone, `honestX` Y alone,
`honestX,honestY` the link alone.

- `a2a_machine.pv` (v2) is checked in all four: every query holds.
- `a2a_today.pv`: ProVerif does not terminate on its private-channel
  variants (replicated frame loops behind private forwarders). Its `T`
  results hold for them anyway: making a channel private only takes
  capabilities from the attacker, so every trace of a variant is a trace
  of the all-public model (secrecy and correspondence are monotone). Its
  attacks need only the link: an honest relay forwards everything it gets
  on the link to its machines and everything they send onto the link, so
  the attacker on the link reads, injects, replays and re-addresses (the
  routing id travels in the clear) exactly as in the traces of the
  all-public model.

No property here holds only with one relay; none is weaker with two. A
relay rerouting a call to a third machine is the attacker changing the
routing id on its hop (`RelayY` routes on it): finding F3 today, refused
by v2 (query 5).

Witnesses: each model ends with reachability queries for its honest flows
(R gets B's response, R gets B's request, B gets R's end of stream); they
must read `F` (reachable), so no `T` above is true because a flow never
completes.

## Queries and results

`a2a_today.pv` (positions in `expect.txt`):

| # | query | today |
|---|---|---|
| 1 | secrecy of R's request to B | **F** (F3) |
| 2 | secrecy of B's response to R | T |
| 3 | secrecy of B's request to R | T |
| 4 | secrecy of R's response to B | T |
| 5 | R as caller agrees with the machine its ack's key id names (txn, both keys, key id), injective | T |
| 6 | R as caller agrees with the target it called | **F** (F3) |
| 7 | a request R handles under B's key id was sent by B | **F** (F1: R's own response reflected) |
| 8 | each request B handles was sent once by R (injective frames) | ? (F2: a replayed frame decrypts again) |
| 9 | what R reads as B's response, B sent | **F** (F1: R's request reflected) |
| 10 | no frame of revoked D handled after the revoke | T (mutant `skip-valid`: F) |
| 11 | no handshake of revoked D answered after the revoke | T (mutant `skip-peer-revoke`: F) |
| 12-13 | witnesses: R gets B's response; R gets B's request | F (reachable) |

`a2a_today_0rtt.pv`:

| # | query | today |
|---|---|---|
| 1 | secrecy of R's early request to B | **F** (F3: C's label for B's agent id) |
| 2 | secrecy of B's response | T |
| 3 | B took request x on txn t only if R sent it there (non-injective) | T |
| 4 | the same, injective | **F**: NK 0-RTT is replayable by design (below) |
| 5 | R's peer is the machine the label's key id names | T |
| 6 | R's peer is the target R called | **F** (F3) |
| 7 | what R reads as the response, the label's machine sent (one key per direction) | T |
| 8 | witness: R gets B's response | F (reachable) |

`a2a_today_unkeyed.pv`: secrecy of the request **F**, agreement **F**: the
relay runs one handshake with each end (F4, expected); witness F.

`a2a_machine.pv` (Part 2), every variant and `leak` (phase 2 leaks the
root key, so every machine key: forward secrecy of all earlier calls):

| # | query | v2 | fails under mutant |
|---|---|---|---|
| 1-4 | secrecy of both directions, R calling B and B calling R, with C and D leaked and the relays' CA the attacker's | T | `drop-psk`, `relay-cert`; 1 also `no-target-check` |
| 5 | R as caller agrees with the target it called (txn, keys, key id), injective | T | `drop-psk`, `relay-cert`, `drop-txn`, `no-target-check` |
| 6 | R as callee: the caller it answered as machine n is n, on that txn and key (non-injective: msg1 replays, and gets no frame accepted, 8) | T | `drop-psk`, `relay-cert`, `drop-txn` |
| 7 | each request B handles was sent once by R | T | `drop-psk`, `relay-cert`, `drop-txn` |
| 8 | each request R handles under B's key id was sent once by B | T | `drop-psk`, `relay-cert`, `drop-txn` |
| 9 | no reflection | T | `drop-psk`, `relay-cert`, `drop-txn`, `no-target-check` |
| 10 | the end of a stream is the sender's | T | `drop-psk`, `relay-cert`, `drop-txn` |
| 11 | no frame of revoked D after the revoke | T | `skip-revoke` |
| 12 | no handshake of revoked D after the revoke | T | `skip-revoke` |
| 13-15 | witnesses: R gets B's response, B's request, B gets R's end | F (reachable) | |

`a2a_machine_0rtt.pv` (Part 2): the today queries, now 1 T, 4 F (by
design, as today), 6 T; `leak` (B's machine key leaks after the calls):
1 T; `leak-static` (B's machine key and its process's static key leak):
1 **F**, as NK specifies (early data is protected by the responder's
static key, not forward secret against its compromise; the static key is
held in memory only, per process); `no-target-check`: 1 and 6 F.

`expect.txt` lists every result exactly, mutants included (a mutant
also fails queries it does not target, e.g. `drop-txn` breaks agreement
everywhere but not secrecy).

Conformance: these are symbolic models of a message exchange, not state
machines, so there is no trace recorder; the code is tied to the model by
its key-schedule vectors (`TestA2AE2EE0RTTKeyScheduleVectors`; v2 adds
`TestA2AE2EEv2Vectors`) and by the code map below (the drift check makes
a change to those files update the models or carry `Spec-Reviewed`).
Runtime: about 9 CPU minutes for all lines (490 s user on a Mac at load
average 40-60), most of it the four `a2a_machine_0rtt` lines; lines run
side by side (`PROVERIF_JOBS`).

## 0-RTT replay

A first flight is replayable by design (query 4). What the code does
about it (`client/rpcclient/a2a_e2ee_0rtt.go`): every flight's ephemeral
key is burned in a per-process register before anything else is judged
(`accept`, `burn`), for two windows; the timestamp must be within 60 s
(`a2aE2EE0RTTWindow`); the static key is per process and in memory only, so
a restarted agent refuses old flights as stale; a full register refuses
everything for two windows (busy); a refusal for replay is never retried
by the caller (`takeRetry`). So a flight is taken at most once by the
process it was made for, and never by another. The register is a stateful
check ProVerif does not model; its tests are `TestA2AE2EE0RTTReplayAndTamperRefused`
and `TestA2AE2EE0RTTRegisterBounded`. A TLA+ model of the register is open
(nfltr `LEFTOVERS.md` A2AID).

## Findings (lane A2AID, 2026-11-07; open, fixed by wire v2)

- **F1 (medium) reflection.** The interactive handshake derives one
  session key for both directions and frames carry only the txn as AAD
  (`a2a_e2ee.go` `deriveA2AE2EESessionKey`, `encrypt`/`decrypt`,
  `a2aE2EEAAD`); a 0-RTT call that falls back keeps that key (`adopt`). The
  relay returns a frame to its sender, which opens it as the peer's: a
  caller reads its own request as the response, a handler its own response
  as a new request. Traces: `a2a_today` queries 7 and 9.
- **F2 (medium) no frame order, no authenticated end.** Frames have random
  nonces and no counter; the end of a stream (an empty `Eom` frame) and
  error frames are in the clear, and `clientStream.statusDetail` shows the
  plaintext payload when it does not decrypt. The relay replays, drops or
  reorders frames within a call, ends a stream early as a clean EOF, and
  forges a peer's error text. Query 8 (ProVerif finds no proof; the replay
  is: send the same DATA frame twice on the txn) and by reading the code.
- **F3 (high) the callee is not bound to the agent called.** Nothing
  compares the ack's key id (interactive, `complete`) or the label's key
  id and name (0-RTT, `parseA2AE2EEStaticLabel`, `Agent.Call`) with the
  target agent id, and the tags do not cover it. A relay reroutes a call to
  another machine of the owner unnoticed; with any one compromised machine
  key, the relay plus that machine read every request a root holder sends
  to any machine (a 0-RTT label may even claim another agent's name under
  the compromised key). Traces: `a2a_today` 1, 6; `a2a_today_0rtt` 1, 6.
- **F4 (expected) no pairing key, no authentication.** Without a pairing
  key or keyring the relay runs a handshake with each end
  (`a2a_today_unkeyed`; `TestA2AE2EEWithoutPairingKeyIsOpenToAnActiveRelay`).
  The docs must say that E2EE without a key protects only against a
  passive relay.
- **F5 (low)** a machine answers a root holder's init (key id "") without
  checking its tag (`newServerA2AE2EEState`): authentication is implicit
  (no frame of such a call decrypts for anyone without the machine's key,
  query 5 holds), but anyone can start the machine's handler. v2 removes
  the case (the caller names the callee's key id).
- Revocation holds at the root holder (10, 11; each check alone is caught
  by its mutant). A revoked machine itself learns nothing: frames a root
  holder sealed before the revoke still open there, which is harmless.

## Code map

| model | code |
|---|---|
| handshake, keys, frames | client/rpcclient/a2a_e2ee.go |
| 0-RTT flight, label, register, retry | client/rpcclient/a2a_e2ee_0rtt.go |
| responder policy | client/rpcclient/a2a_e2ee_agent.go |
| frames on the streams | client/rpcclient/client_stream.go, client/rpcclient/server_stream.go |
| runner, prover pin | spec/proverif/run.sh, scripts/fetch-proverif.sh |
