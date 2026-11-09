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
| AES-256-GCM is an AEAD; a nonce never repeats under one key (v1: random 96-bit nonces; v2: Noise's 64-bit counter per direction) | NIST SP 800-38D (2^32 random-nonce messages per key); Noise rev. 34 §5.1 |
| Noise NNpsk0 as specified | Noise Protocol Framework rev. 34, `github.com/flynn/noise` |
| the HMAC input encoding `label 0 txn 0 keys` is injective | the labels are prefix-free; the keys after the second 0 have fixed length (`a2a_e2ee.go` `a2aE2EEPairingTag`) |
| a call's frames reach the other end in order, unless the relay misbehaves | gRPC stream per agent, relay-core sessions (relied on by v2's counters only) |
| the root pairing key and machine keys never pass through a relay | nfltr `a2akeys`: files made on a root holder, copied out of band |

## Models

| file | what |
|---|---|
| `a2a_today.pv` | wire v1 (removed; relay 3977c04, the findings' evidence): interactive handshake, frames, machine keys, revoke; root holder R on relay X, machines B, E (honest), C (leaked), D (leaked, revoked at phase 1) on relay Y |
| `a2a_machine.pv` | wire v2, what `client/rpcclient` ships: Noise NNpsk0 under the owner-derived machine key, key id from the called agent id, prologue binding txn, the initiator's role, caller, callee and key id (the callee's own ref the relay's), per-direction counter keys, authenticated end; each rule cites its code |

Wire v2 is interactive only: v1's 0-RTT first flight (Noise NK to a
static key advertised as a connect label, its replay register and NK's
early-data limit) is gone, with its models (lane A2AV2, the hub's default;
cost: one more round trip per E2EE call).

Two relays (the owner's 2026-11-07 addition): caller on X, callee on Y,
frames over the link (today the replica link, `relay-server`
`core/replicas`). Flags `honestX`, `honestY` make that relay's hops private
channels with an honest forwarding process (Y routes by agent id, stamps
the source by connection); the link is public in every variant, since a
compromised relay holds its end of it. So the variants are: `-` both
relays (colluding), `honestY` X alone, `honestX` Y alone,
`honestX,honestY` the link alone.

- `a2a_machine.pv` (v2) is checked in all four: every query holds. With
  sessions (`sess`) ProVerif does not terminate on `honestX,honestY`;
  that variant's `T` results follow from `sess,honestX` (or
  `sess,honestY`) by the monotonicity below, and its witnesses are
  checked in the others, so it is not run.
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

`a2a_today.pv`, wire v1 (positions in `expect.txt`):

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

`a2a_machine.pv` (wire v2), every variant and `leak` (phase 2 leaks the
root key, so every machine key: forward secrecy of all earlier calls):

| # | query | v2 | fails under mutant |
|---|---|---|---|
| 1-4 | secrecy of both directions, R calling B and B calling R, with C and D leaked and the relays' CA the attacker's | T | `drop-psk`, `relay-cert`; 1 also `no-target-check` |
| 5 | R as caller agrees with the target it called (txn, keys, key id), injective | T | `drop-psk`, `relay-cert`, `drop-txn`, `no-target-check`, `warm-untyped` (sessions) |
| 6 | R as callee: the caller it answered as machine n is n, on that txn and key (non-injective: msg1 replays, and gets no frame accepted, 8) | T | `drop-psk`, `relay-cert`, `drop-txn` |
| 7 | each request B handles was sent once by R | T | `drop-psk`, `relay-cert`, `drop-txn`, `drop-role` (F6), `early-data` (A2AWARM) |
| 8 | each request R handles under B's key id was sent once by B | T | `drop-psk`, `relay-cert`, `drop-txn` |
| 9 | no reflection | T | `drop-psk`, `relay-cert`, `drop-txn`, `no-target-check`; `one-key` (F1) now only `?` on 8 and 17: the response's first frame is a HEADER, which no request frame is, so in the model (one frame each way) a reflected frame is refused by its type too; the code's later DATA frames are what the split keys keep apart |
| 10 | the end of a stream is the sender's | T | `drop-psk`, `relay-cert`, `drop-txn`, `clear-end` (F2) |
| 11 | no frame of revoked D after the revoke | T | `skip-revoke` |
| 12 | no handshake of revoked D after the revoke | T | `skip-revoke` |
| 13 | revoke ends the session: no resumed call of revoked D answered after the revoke | T | `survive-revoke` |
| 14 | a session is its pair's: R's request to B is never handled by E | T | `sess-unbound`, `no-target-check` |
| 15 | no nonce reuse: a key seals at one nonce in one call only | T | `counter-reset` |
| 16-18 | 7, 8, 10 for every call, handshake or resumed (non-injective): no cross-call splice or replay into another call | T | `txn-unbound` (16-18), `drop-psk`, `relay-cert`, `drop-txn`, `drop-role` (16, F6) |
| 19-21 | witnesses: R gets B's response, B's request, B gets R's end, on a handshake | F (reachable) | |
| 22-24 | the same on a resumed call | F (reachable) | |
| 25 | response headers are the callee's: the headers R takes on call t are the machine's on t (sealed with its first response, frame type HEADER) | T | `clear-header`, and the mutants that break the frames' keys |

Sessions (lane A2ASESS, flag `sess`: the lines without it are wire v2
with a handshake every call, where 13-18 hold trivially and the resumed
witnesses 22-24 read T, unreachable): 5-8 and 10 are over handshake calls (`HS`), as
ProVerif's injectivity cannot hold across a table read and write; a
resumed call is served at most once by the callee's replay window, which
`spec/A2ASession.tla` checks (`AtMostOnce`, mutant `AS:no-window`), with
the callee's restart, expiry and the one rehandshake after a refusal. The
model's resume, tag and call keys are `client/rpcclient/a2a_e2ee_session.go`;
each query and mutant has a test in `a2a_e2ee_session_test.go`
(`TestA2AE2EESessionBoundToPair` 14, `TestA2AE2EEResumedFrameNotInAnotherCall`
16-18, `TestA2AE2EEResumedCallReplayRefused` and `TestA2AE2EESessionWindow`
the window, `TestA2AE2EECallKeysUnique` 15, `TestA2AE2EERevokeEndsSession` 13,
`TestA2AE2EERotationRekeys`, `TestA2AE2EEResponderRestartRehandshakes`); the
wire vectors gain the session secret, its id, a resume and its first frames.
The retry after an unknown (its message 1 names the resume it retries) is
a state property, `spec/A2ASession.tla` (finding S1 there).

Warm (lane A2AWARM, `Agent.WarmA2AE2EE`, `handleE2EEWarm`): a handshake
with no call, so a peer's first call resumes (no round trip before its
request). The model runs warms beside calls (`RootWarm`, `MachWarm`,
with `sess`); every query holds. Message 1's payload says it is a warm
(`a2aWarmMark`; a call's is empty or a retry), so its AEAD binds the type:
a relay that retags a warm as an init, or an init as a warm, is refused
(mutant `warm-untyped`, the warm's payload empty: R accepts a call the
machine took as a warm, and 5 fails; `TestA2AE2EEWarmRetagRefused`). A request
never rides the handshake (no 0-RTT): message 1's payload is sealed
under the psk and the initiator's e alone, so a relay replays it to the
machine, which opens it again (mutant `early-data`: the request in
message 1 and served on receipt fails 7, injective delivery).

`expect.txt` lists every result exactly, mutants included (a mutant
also fails queries it does not target, e.g. `drop-txn` breaks agreement
everywhere but not secrecy).

Conformance: these are symbolic models of a message exchange, not state
machines, so there is no trace recorder; the code is tied to the model by
its wire vectors (`TestA2AE2EEv2Vectors`: prologue, psk, both handshake
messages and the first frames of each direction, the model's term beside
each), by its bindings ("Bindings" below: a row per field the model
binds, each a relay's change the code must refuse), by each rule's file:line citation in `a2a_machine.pv`, by one test
per finding (`client/rpcclient/a2a_e2ee_v2_test.go`: F1
`TestA2AE2EERefusesReflectedFrame`; F2 `TestA2AE2EERefusesReplayedFrame`,
`TestA2AE2EERefusesDroppedFrame`, `TestA2AE2EERefusesForgedEnd`; F3
`TestA2AE2EERefusesReroute`; each fails on v1) and by the code map below
(the drift check makes a change to those files update the models or carry
`Spec-Reviewed`). Runtime: about 4 CPU minutes for all lines (229 s user,
82 s wall on a Mac at load average 7-10); lines run side by side
(`PROVERIF_JOBS`).

## Bindings

The vectors pin the bytes the code sends; a change to the wire re-pins
them, and a re-pinned vector cannot tell a dropped binding from a new
field. So each model lists, as `BIND:<id>` lines in a comment, the fields
and keys of its messages that its queries rely on and a relay could change
on the wire, and a Go test has one row per id: it changes just that field
in an honest message of the real code (fixed keys, as the vectors) and
requires a refusal. The test fails when the model's ids and its rows
differ, so a binding added to a model needs its row, and a row outlives any
re-pinning (`make spec-bindings`, in `make ci`; nfltr
`docs/decisions/e2ee-model-code-link-2026-11-09.md`).

| model | test | rows |
|---|---|---|
| `a2a_machine.pv` | `client/rpcclient/a2a_e2ee_bindings_test.go` `TestA2AE2EEModelBindings` | 17: message 1 (txn, role, caller, callee, key id, psk, warm), the ack's transcript, frames (direction, order, end, header), resumed calls' keys (txn, call number), the resume (txn, call number, pair) |

A planted Go mutant fails its row (lane E2EEVECTORS): the role, caller,
callee or txn left out of `a2aE2EEPrologue`, the psk not keyed, a warm's
message 1 untyped, a call's keys or a resume's tag without the call number,
a resume's tag without the txn. Where the existing hostile-relay tests
already make the attack (`frame.end`, `frame.header`, `init.warm`,
`resume.pair`), the row runs them.

## Findings (lane A2AID, 2026-11-07; F1-F3 and F5 fixed by wire v2, lane A2AV2)

- **F1 (medium) reflection.** The interactive handshake derives one
  session key for both directions and frames carry only the txn as AAD
  (`a2a_e2ee.go` `deriveA2AE2EESessionKey`, `encrypt`/`decrypt`,
  `a2aE2EEAAD`); a 0-RTT call that fell back kept that key (`adopt`). The
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
  to any machine (a 0-RTT label could even claim another agent's name
  under the compromised key). Traces: `a2a_today` 1, 6 (and v1's 0-RTT
  model, removed with the flight).
- **F4 (expected) no pairing key, no authentication.** Without a pairing
  key the relay runs a handshake with each end (Noise NN). Removed: A2A
  E2EE is keyed only (lane A2AFINAL; `Dial` refuses `WithA2AE2EE` without
  a key, `ErrA2AE2EENoKey`, and an agent without keys refuses every E2EE
  call), so its model and the unkeyed Noise NN are gone.
- **F5 (low)** a machine answers a root holder's init (key id "") without
  checking its tag (`newServerA2AE2EEState`): authentication is implicit
  (no frame of such a call decrypts for anyone without the machine's key,
  query 5 holds), but anyone can start the machine's handler. v2 removes
  the case (the caller names the callee's key id).
- **F6 (medium, lane A2AREF, fixed before release) reflection to the
  caller's own machine.** A callee's own ref is the one the relay states
  at connect (`agentwire.AgentRefKey`, `Agent.Ref`): the model takes it
  from the attacker at every answer. With the prologue binding only txn,
  caller, callee and key id, a relay returns a machine's call to R to that
  machine, or to another agent of it (same machine key), told "you are
  R"; it answers and handles its own request as R's (queries 7, 16).
  Fixed by the initiator's role in the prologue (`a2aE2EERole`: a machine
  answers root holders only, a root holder a machine key id from a
  machine; `A2AE2EEKeyring.Machine`); mutant `drop-role`; test
  `TestA2AE2EEMachineInitNotAnsweredByAMachine` (sibling and itself).
  Root holders hold one root key and stay interchangeable: a relay can
  route a call between them whatever the callee check (Open item 2).
- Revocation holds at the root holder (10, 11; each check alone is caught
  by its mutant). A revoked machine itself learns nothing: frames a root
  holder sealed before the revoke still open there, which is harmless.

## E2EE paths: pinned TCP, WireGuard, P2P (lane E2EEPROOF, 2026-11-07)

`e2ee_tcp.pv`, `wg_exit.pv` and `p2p_e2e.pv` model the other E2EE paths
whose ends live in this repository (Part 3 of `expect.txt`); nfltr's
`docs/e2ee.md` "Formal proofs" is the overview of every path. The
attacker owns every relay: with two relays (each end on another relay or
replica, the replica link between them, a relay rerouting a session to a
third machine) one Dolev-Yao attacker plays all of them, which is the
colluding case and so covers each relay hostile alone. A query that holds
holds for two relays too; none needs one relay.

Not re-proven: TLS 1.3, WireGuard's Noise IKpsk2, DTLS-SRTP. Each is an
ideal channel to the holder of the key its end checked (citations in each
model and below). Modelled is ours: where each end gets the other's key or
fingerprint, the check, the pairing key, rotation, the plaintext
fallbacks a relay could steer to. An F on a model's base line is a
documented limit or a finding (nfltr's LEFTOVERS, lane E2EEPROOF).

### e2ee_tcp.pv: pinned TCP sessions (Track A)

`nfltr dial|tcp-connect|ssh-proxy --pin`, `pin:` on a `connect:` mapping,
to an agent ending TLS with its E2EE certificate (`Config.TCPE2EEOnly`, a
service table's `e2ee: true` service).

| # | query | result |
|---|---|---|
| 1 | payload secret (pin from the agent's own output, target fixed by the agent) | holds |
| 2 | injective agreement: a response the client accepts came from the pinned key in that session | holds |
| 3 | `nfltr tcp --e2ee` without `--forward`: payload secret | holds: the agent refuses a pinned session without a target of its own (`ErrE2EENoFixedTarget`, `ERROR_REASON_TARGET_REFUSED`); before lane E2EEFIX it dialled the relay's target (finding 1, mutant `relay-names-target`) |
| 4 | rotation: the old key leaks; a client pinned to the new certificate | holds |
| 5 | ... a client still pinned to the old certificate | attack: a rotation revokes no pin; re-pin |
| 6 | first use: a pin taken from what the relay shows (dashboard), or an SSH host key on first use (`nfltr shell`: OpenSSH known_hosts; a new key every start without `--host-key`) | attack |
| 7 | the agent's service, against the relay | holds: the agent requires a client certificate whose key is on its list (`TCPE2EEClients`, a service's `E2EEClients`; finding 2, lane E2EEFIX2); before, no client authentication (mutant `any-client-cert`: an agent without a list, and a relay-CA client certificate, which the relay can mint) |
| 8 | a removed client key (leaked) reaches nothing: removal from the list is revocation | holds |
| 9 | what reaches the service was sent by the allowed client | holds |
| 10 | witness: an allowed client reaches the service | attack (reachable), as it must |
| 11 | a clean end the client passes on (after the bytes it read) was the pinned agent's close_notify after those bytes | holds: a stream that ends without the peer's close_notify (the relay cutting it between two records) is a reset to the local application (`client/tlsend`; claims review CLAIMS-A Q5, mutant `clear-end`: crypto/tls's `io.EOF` for both, the code before) |
| 12 | the service's half close was the allowed client's close_notify after the bytes it got | holds (the agent side, `serveE2EETCP`; mutant `agent-clear-end`) |
| 13, 14 | witnesses: both clean ends happen | attack (reachable), as they must |
| 15 | a clean end at the client was the target's clean end | holds: a target's reset (or a read error other than EOF at the agent) ends the TLS stream without close_notify (`tlsend.Conn.Reset`, which link's `peerlink.Join` calls on an abort), a reset at the client; lane TCPRESET, mutant `abort-as-close`: Join closed the TLS conn, sending close_notify, the code before |
| 16 | the service's half close was the client's local application's clean end | holds: the application's reset (a local read or write error) resets the session (nfltr `transportcli.Pump`, `tlsSession.Reset`); mutant `client-abort-as-close` |
| 17, 18 | witnesses: both aborts happen | attack (reachable), as they must |

A TLS record is bound to its place in its direction's stream (TLS 1.3's
sequence number in the AEAD nonce): the model's close record names the
bytes it follows. Without that binding the model finds the attacker
splicing one agent session's close record onto a replay of the client's
handshake to another; TLS's sequence numbers and the server's random
rule it out, and the model does not re-prove TLS.

Mutants: skip the pin check, a relay-supplied pin, plaintext when the relay
gives no answer, the relay's target without `--forward` (finding 1 before
its fix), the relay's target despite `--forward`, accept a response
without the session key, the agent takes any client certificate
(`any-client-cert`), skips CertificateVerify (`skip-certificate-verify`),
a raw end taken as a clean end on the client (`clear-end`) or the agent
(`agent-clear-end`), an end's reset sent as close_notify at the agent
(`abort-as-close`) or the client (`client-abort-as-close`).
A client-side mutant leaves 7-9 holding: the agent's check of the client
does not depend on the client's check of the agent. An agent with an
empty list is `any-client-cert`: the SDK's zero value authenticates no
client, and the default of nfltr's agent commands is nfltr's
(`docs/decisions/e2ee-fix-2026-11-07.md` "Lane E2EEFIX2").
The design model `e2ee_tcp_clientauth.pv` (lane E2EEFIX) is folded into
this one and deleted.

### e2ee_tcp_org.pv: pinned TCP in organisation mode (lane ORG2)

A tcp service in organisation mode (`agent.Service.Org`, `AllowGroups`;
nfltr `allow_group:`) ends its sessions' TLS with its machine
certificate, issued under the organisation's root (nfltr
`docs/decisions/org-enrolment-2026-11-09.md`); a client names the machine
(`nfltr dial web/pg`, `to: web/pg` with `org: true`) and checks the
chain and the name, no pin; the service admits a client certificate of
the organisation in an allowed group. The attacker owns the relays and
holds the keys of eve (live, another group), lost (revoked), old
(expired), and an expired and a revoked key of web itself. Who can get a
certificate at all is nfltr's `enrol.pv`; the times (a session ends at
`Identity.Until`, a newer CRL cuts what it lists) are nfltr's
`spec/enrol/Enrol.tla` (`NoExpiredSession`, `RevocationBound`), whose
session-level mutants `no-expiry-timer` and `no-cut-on-update` are Go
mutants of `client/agent` (`make test-go-mutants`).

| # | query | result |
|---|---|---|
| 1 | the client's bytes reach only machine web | holds |
| 2 | injective agreement: the answer the client takes, web's agent sent in that session | holds |
| 3, 4, 5 | the client refuses a server certificate of another name, a revoked one, an expired one | holds |
| 6 | the service's answer reaches only an admitted client | holds |
| 7 | what reaches the service was sent by an admitted client | holds |
| 8, 9, 10 | the service refuses a client outside its groups, a revoked one, an expired one | holds |
| 11, 12 | witnesses: an allowed client reaches the service and gets its answer | attack (reachable), as they must |

Mutants, each check its own, the client's and the service's apart:
`client-no-chain-check` (a certificate the relay made), `no-name-check`
(another machine's), `client-no-expiry-check`, `client-no-crl-check`;
`agent-no-chain-check`, `no-group-check`, `agent-no-expiry-check`,
`agent-no-crl-check`. No downgrade: a client or service is in one mode,
set by its own configuration, and never falls back. `downgrade-plain`
(the client sends in plain when the relay answers that the service is
pinned) fails 1; `downgrade-any-client` (the service serves a client
without an organisation certificate, the pin mode's "no list") fails 6
and 7.

### wg_exit.pv: WireGuard client and exit (Track B)

The preshared key is HMAC(K, "nfltr-wg-psk-v2", the exit's service name,
key id), K the exit's A2A key: the root key, or the machine key of the key
id the exit says (relay-server hands it to the client as
`x-wg-peer-key-id`, its word, as A2A's learned machine; a machine client
holds only its own). A root client takes that key id only when it is the
machine the client named (lane ROOTNAMEPIN, nfltr a2akeys
`PairKeys.Target`): the machine id of a ref `<machine id>-<service>`, the
id its own machine store holds for `<machine name>.<service>` (the name
the owner gave `machines add`), or the root key for a bare service name;
never the relay's word. Before, it derived whatever machine the relay
named, so a relay could steer `m1.lan` to `lan` on another of the owner's
machines, or, holding a leaked machine key, sit in the middle. Each end
binds its own name for the exit: the client the one it named, the exit
its own. No wire change: the key id in the preshared key already names
the machine.

| # | query | result |
|---|---|---|
| 1 | paired: a client's payload secret unless the machine it named is leaked | holds (before ROOTNAMEPIN only "unless the key id the relay names is a leaked machine's") |
| 2 | paired: injective agreement exit <- client on the exit name, the machine named (its key id), both keys and the payload (home1 on two machines; an exit on the root key) | holds |
| 3 | unpaired: payload secret | attack: the relay hands each end its own key (documented) |
| 4 | two exits on one machine key, the relay reroutes a client to the other: the exit that got it is the one the client named | holds (finding 5 fixed: the name is in the key) |
| 5 | a client that named m1 gets nothing to a leaked machine key, whatever key id the relay names | holds |
| 6 | the key id a client used is the machine it named | holds |
| 7-8 | witnesses: a paired payload arrives at home1 on m1, and at the second home1, on m2 | reachable |

`x-wg-paired` is advisory: each end applies its own preshared key whatever
the relay says. Mutants: drop the preshared key on the relay's word, no
preshared key at the client, none at the exit, `group-key` (one key for
all machines: v1's group secret), `name-unbound` (the exit's name not in
the preshared key: v1, finding 5; since the machine check only 4 fails:
the name keeps apart exits of one machine), `relay-kid` (a root client
takes the relay's key id: the code before ROOTNAMEPIN; fails 1, 2, 5, 6).

### p2p_e2e.pv: P2P sessions (calls, file transfer, the call page)

The HKDF salt is HMAC(K, "nfltr-p2p-e2e-v2", the responder's service name,
the pair key id), K the pair's A2A key: the root key between two root
holders, else the machine key of the end that is a machine. The offer
carries the initiator's key id, the answer the responder's (the relay's
word); a root end derives the machine key of the peer's key id, a machine
end holds only its own and takes a root peer or one of its own machine. A
root initiator takes the answer's key id only when it is the machine it
named, from its own store (lane ROOTNAMEPIN, as `wg_exit.pv`); a
responder names no peer. Queries 1-4 are about paired ends (a key file on
both).

| # | query | result |
|---|---|---|
| 1 | paired: data secret unless the pair key id is a leaked machine's | holds |
| 2 | paired: browser media secret (DTLS fingerprint in a sealed signaling frame), same condition | holds |
| 3 | paired: injective agreement responder <- initiator on the responder's name, pair key id, sid, both keys, data (finding 5: a call rerouted to another responder of the same machine is refused) | holds |
| 4 | paired: injective agreement on the key confirmation | holds |
| 5 | unpaired: data secret | attack: the relay in the middle (documented) |
| 6 | unpaired: equal fingerprints on both machines imply the same two keys | holds |
| 7 | a root initiator's data to home1 secret unless the machine it named is leaked (lane ROOTNAMEPIN; 1 holds only "unless the pair key id is a leaked machine's") | holds |
| 8 | ... and the pair key id it used is the machine it named | holds |
| 9 | responder home1 on machine k <- an initiator that named k, injective (home1 on two machines) | holds |
| 10 | witness: a root initiator's data reaches a responder on a machine key | reachable |
| 11 | witness: a machine initiator's data reaches a root responder | reachable |
| 12 | witness: the second home1, on m2, reached by an initiator that named m2 | reachable |

Query 6 is symbolic; computationally it is an 80-bit second preimage (one
side's fingerprint is fixed before the relay picks its second key).
Mutants: no pairing salt, skip the responder's confirmation check, old
protocol in plaintext, accept any DTLS fingerprint, the SDP unsealed,
fingerprints not compared, `group-key` (one key for all machines: v1's
group secret), `name-unbound` (the responder's name not in the salt,
finding 5), `relay-kid` (a root initiator takes the relay's key id: the
code before ROOTNAMEPIN; fails 7-9). Below the model (nonces are not symbolic): a
SignalConn frame no path took gave its sequence number back
(`sigconn.go` `sendSeq--`), so a frame partly written before its error was
followed by another sealed under the same nonce (finding 4); since lane
E2EEFIX a failed write spends its number and ends the SignalConn
(`TestSignalConnFailedWriteEndsIt`). The data path's records had the same
gap until lane CLAIMS-A: `e2e.go` `secureConn.Write` advanced its sequence
number only after a write succeeded, so a record write that failed in part
(a write deadline) left the next `Write` sealing other bytes under the same
nonce; a failed record write now spends its number and every later `Write`
fails (`TestSecureConnFailedWriteEndsIt`).

### First use

| path | what the first contact trusts |
|---|---|
| pinned TCP | the fingerprint the agent printed, carried by the user; never the relay's |
| `nfltr shell` | OpenSSH's first-use prompt; every start without `--host-key` is a first use |
| WireGuard unpaired | the relay, on every connect; paired: the pairing file, copied out of band |
| P2P unpaired | the relay, unless the users compare the fingerprints; paired: the pairing file |

### Environment assumptions of these paths

| assumption | source |
|---|---|
| TLS 1.3 with a checked server key is an authenticated channel; no resumption skips the pin check | Cremers et al., IEEE S&P 2017; Bhargavan et al., IEEE S&P 2017; `e2eeTLSConfig` sets no session cache |
| Noise IKpsk2 gives a key only to the holder of the peer key it used and the same psk | Donenfeld and Milner 2017 (Tamarin); Dowling and Paterson, ACNS 2018; Lipp, Blanchet and Bhargavan, EuroS&P 2019 |
| DTLS-SRTP keys only the holder of the fingerprinted certificate | RFC 5763, RFC 8827 |
| X25519 refuses low-order points | Go `crypto/ecdh` (`ECDH` errors on the all-zero output) |
| SHA-256, HKDF, HMAC, AES-GCM are ideal | standard; nonces unique per key (see the SignalConn finding) |

## Code map

| model | code |
|---|---|
| handshake, keys, frames | client/rpcclient/a2a_e2ee.go |
| sessions: resume, call keys, window | client/rpcclient/a2a_e2ee_session.go, client/rpcclient/a2a_e2ee_session_test.go |
| responder policy | client/rpcclient/a2a_e2ee_agent.go |
| frames on the streams, the end of a served call, v1 refused | client/rpcclient/client_stream.go, client/rpcclient/server_stream.go, client/rpcclient/a2a.go |
| one test per finding, wire vectors | client/rpcclient/a2a_e2ee_v2_test.go |
| runner, prover pin | spec/proverif/run.sh, scripts/fetch-proverif.sh |
| e2ee_tcp.pv | client/relaytrust/relaytrust.go |
| e2ee_tcp.pv | client/agent/session_plan.go |
| e2ee_tcp.pv | client/agent/tls.go |
| e2ee_tcp.pv | client/agent/agent.go |
| e2ee_tcp.pv | client/agent/e2ee_client_keys.go |
| e2ee_tcp.pv | client/agent/services.go |
| e2ee_tcp.pv | client/tlsend/tlsend.go |
| e2ee_tcp_org.pv | client/agent/org.go |
| e2ee_tcp_org.pv | client/agent/testdata/org_mutants.txt |
| wg_exit.pv | client/wg/keys.go |
| wg_exit.pv | client/wg/tunnel.go |
| wg_exit.pv | client/agent/wgexit/wgexit.go |
| wg_exit.pv | proto/wire/wgwire/wgwire.go |
| p2p_e2e.pv | client/p2p/e2e.go |
| p2p_e2e.pv | client/p2p/rtcdata.go |
