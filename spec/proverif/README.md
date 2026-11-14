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
`docs/decisions/e2ee-model-code-link-2026-11-09.md`). A model whose
bindings test is missing would be checked by nothing:
`client/model_bindings_guard_test.go` `TestEveryModelBindingHasARow` (in
`make test`) fails when a model declares a `BIND` id that no
`*_bindings_test.go` has as a quoted row key, or whose test `make
spec-bindings` does not run, unless its `pendingBindings` lists the id with
where its row is.

| model | test | rows |
|---|---|---|
| `a2a_machine.pv` | `client/rpcclient/a2a_e2ee_bindings_test.go` `TestA2AE2EEModelBindings` | 17: message 1 (txn, role, caller, callee, key id, psk, warm), the ack's transcript, frames (direction, order, end, header), resumed calls' keys (txn, call number), the resume (txn, call number, pair) |
| `e2ee_tcp.pv` (direct paths) | `client/agent/direct_bindings_test.go` `TestDirectModelBindings` | 6, one per `BIND:direct.*`: a look-alike certificate and another machine's name answering the punch (`refused_cert`), the token keyed by another session, bound to another or no QUIC connection, the other role's token (both ways), another epoch's token (lane DIRECTPATH3; Go mutants `direct-no-name`, `direct-no-cert-check`, `token-no-epoch`, `token-unbound`, `token-no-role`, `direct-no-token`). Under a group dial (36), `TestDirectGroupDialGoesDirectToItsInstance`: the relay's pick of the other instance for the first exchange refused and excluded, the session's instance taken (lane DIRECTGROUP; Go mutants `group-control-no-name`, `group-control-no-exclude`) |
| `e2ee_tcp.pv` (services by name) | `client/agent/service_bindings_test.go` `TestServiceModelBindings` | 3 here, one per `BIND:org.*`: a session routed to pg refuses an offer of web/vault, another agent's pg and no protocol, a session routed to vault refuses web/pg, and the client's `BindServiceTLS` refuses a server that negotiated none (`org.service`); a service published under a group the certificate lacks refused at `NewServiceTable`, and pg@db refused once a renewed certificate lacks db (`org.group`); pg@db refused for a pg published under ops, vault@db for a vault under none (`org.publish`) (lane SVCBIND; Go mutants `client-no-alpn-check`, `agent-no-alpn-check`, `no-protocol-accepted`, `agent-no-publish-check`, `agent-no-ou-check`, `publish-not-in-cert`). The group-dial client's own check (OU contains the group, no name) is `client/orgid/group_dial_bindings_test.go` `TestE2EETCPModelBindingsGroupDialClient` (`org.group`; Go mutant `no-group-check` in `client/orgid/testdata/mutants.txt`). The dialling client's half through `nfnet.Conn`'s organisation TLS is `client/nfnet/dial_bindings_test.go` `TestE2EETCPModelBindingsDialClient`: web/pg refuses web's vault and a server negotiating none (`org.service`; Go mutant caught by hand: `BindServiceTLS` dropped), pg@db reaches machines of db whatever their name and refuses eve (group web), naming her for the next pick's exclude, and a server negotiating vault@db (`org.group`) |
| `wg_exit.pv` | `client/agent/wgexit/wg_exit_bindings_test.go` `TestWGExitModelBindings` | 3 here (psk binds the exit's name; each end's psk on the key the relay told it) + 3 in nfltr `cmd/nfltr/internal/wgcli/wg_exit_bindings_test.go` (the key id of the machine named, psk whatever `x-wg-paired` says, one key per machine) |
| `cap_address.pv` | `client/capaddr/capaddr_bindings_test.go` `TestCapAddressModelBindings` | 4 of 4, one per `BIND:cap.*`, against the codec `client/capaddr` (real TLS 1.3 over a pipe): the answer's key and the TLS certificate's key of another server, and a plain answer with no key (`cap.pin`); the record over another relay, rid, tag or hints, under another key, or none (`cap.rendezvous`); the proof over another session's exporter, under another secret, without the exporter (`cap.secret`); A1's proof at A2's acceptor and A2's at A1's, one key (`cap.service`). Go mutants caught by hand: the answer's key unchecked, the certificate unchecked, the relay out of the record, the exporter out of the proof. `pin-unkeyed` is no binding: `TestRoundTrip` requires two addresses of one key to differ in pin; and 4 of 4 against the transport, `client/nf1/nf1_bindings_test.go` `TestNF1ModelBindings` (lane NF1RDV): a relay routing to another server or running TLS under another key (`cap.pin`), a record over another rid or with hints it does not cover (`cap.rendezvous`), a proof over another exporter (`cap.secret`, no verdict), A1's client at A2's listener (`cap.service`); Go mutants caught by hand: the answer unchecked, `VerifyConnection` dropped, `Admit` skipped; and 1 of 1 for the direct phase (lane NF1DIRECT), `client/agent/direct_nf1_bindings_test.go` `TestNF1DirectModelBindings`: a holder of another key answering the punch at the agent's candidate, for the session's own server name, is refused (`refused_cert`) and the session stays relayed with its bytes intact (`nf1direct.pin`; Go mutant `nf1-direct-no-pin` in `org_mutants.txt`); the tokens are `e2ee_tcp.pv`'s rows (`TestDirectModelBindings`), and the `d1` hint's binding is `cap.rendezvous` (a hint the record does not cover) |

Pending, in `pendingBindings` until their code lands (nfltr
`docs/decisions/nf1-udp-2026-11-14.md`): `dgram.tag` (`cap_address.pv` and
`e2ee_tcp.pv` datagrams, lane UDP3), `cap.kind` (the dial's kind against
the record's `u1`) and `org.kind` (the ALPN's kind prefix `nfltr-dg/`),
lane UDP2.

A planted Go mutant fails its row (lane E2EEVECTORS): the role, caller,
callee or txn left out of `a2aE2EEPrologue`, the psk not keyed, a warm's
message 1 untyped, a call's keys or a resume's tag without the call number,
a resume's tag without the txn. Where the existing hostile-relay tests
already make the attack (`frame.end`, `frame.header`, `init.warm`,
`resume.pair`), the row runs them.

`wg_exit.pv`'s rows run real WireGuard handshakes (wireguard-go on both
ends, the test as the relay) and require the client's to fail: a client
rerouted to another exit of the same machine key (`psk.name`), a paired
client told the relay's exit key (`client.psk`), a paired exit told the
relay's client key (`exit.psk`); an honest pairing completes first. The
client's choices are rows in nfltr (`nfltr.*` ids, listed in the relay test
as `wgNfltrRows`): it takes the relay's key id only for the machine it
named, its psk does not depend on `x-wg-paired`, machine keys differ per
machine. Planted Go mutants caught (lane E2EEVECTORS-2): the service name
out of `PresharedKey`, the client's psk off its peer, the exit's psk off its
tunnel. The key id inside the HMAC has no row: keys already differ per key
id, and no query relies on it.

`client/agent/e2ee_share_bindings_test.go` `TestE2EEShareModelBindingsAgent`
holds the agent's row of relay-core's `e2ee_share.pv` (`relay.agent.cred`:
the share credential checked on every E2EE request; mutant: the check
skipped).

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

## E2EE paths: TCP, WireGuard, P2P (lane E2EEPROOF, 2026-11-07)

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

### e2ee_tcp.pv: TCP sessions in organisation mode (lanes ORG2, ORGCUT)

Organisation mode is the only end-to-end encrypted TCP mode: lane ORGCUT
deleted pins (`--pin`, `pin:`, `Config.TCPE2EEClients`,
`Service.E2EEClients`) and folded `e2ee_tcp_org.pv` into this model. A tcp
service with E2EE On is in organisation mode (`agent.Service.Org`,
`AllowGroups`; a tunnel's `Config.TCPE2EEOrg`, `TCPE2EEAllowGroups`; nfltr
`allow_group:`), else the SDK refuses it. It ends its sessions' TLS with
its machine certificate, issued under the organisation's root (nfltr
`docs/decisions/org-enrolment-2026-11-09.md`); a client names the machine
(`nfltr dial web/pg`, `to: web/pg`) and checks the chain and the name; the
service admits a client certificate of the organisation in an allowed
group, and sends its plaintext only to the target it fixed (its table's,
`--forward`'s). The attacker owns the relays and holds the keys of eve
(live, another group), lost (revoked), old (expired), and an expired and a
revoked key of web itself. Who can get a certificate at all is nfltr's
`enrol.pv`; the times (a session ends at `Identity.Until`, a newer CRL cuts
what it lists) are nfltr's `spec/enrol/Enrol.tla` (`NoExpiredSession`,
`RevocationBound`), whose session-level mutants `no-expiry-timer` and
`no-cut-on-update` are Go mutants of `client/agent` (`make
test-go-mutants`).

| # | query | result |
|---|---|---|
| 1 | the client's bytes reach only machine web's own service | holds |
| 2 | injective agreement: the answer the client takes, web's agent sent in that session | holds |
| 3, 4, 5 | the client refuses a server certificate of another name, a revoked one, an expired one | holds |
| 6 | the service's answer reaches only an admitted client | holds |
| 7 | what reaches the service was sent by an admitted client | holds |
| 8, 9, 10 | the service refuses a client outside its groups, a revoked one, an expired one | holds |
| 11 | a clean end the client passes on was web's agent's close_notify | holds: a stream that ends without the peer's close_notify (the relay cutting it between two records) is a reset to the local application (`client/tlsend`; claims review CLAIMS-A Q5, mutant `clear-end`: crypto/tls's `io.EOF` for both) |
| 12 | the service's half close was the client's close_notify after the bytes it got | holds (the agent side, `serveE2EETCP`; mutant `agent-clear-end`) |
| 13 | a clean end at the client was the target's clean end | holds: a target's reset ends the TLS stream without close_notify (`tlsend.Conn.Reset`, which link's `peerlink.Join` calls on an abort); lane TCPRESET, mutant `abort-as-close` |
| 14 | the service's half close was the client's local application's clean end | holds: the application's reset resets the session (nfltr `transportcli.Pump`, `tlsSession.Reset`); mutant `client-abort-as-close` |
| 15, 16 | witnesses: an allowed client reaches the service and gets its answer | attack (reachable), as they must |
| 17, 18 | witnesses: both clean ends happen | attack (reachable) |
| 19, 20 | witnesses: both aborts happen | attack (reachable) |
| 21 | what the client sends on a direct connection it took reaches only web's agent | holds (design, lane DIRECTPATH) |
| 22 | injective agreement: a direct connection the client takes ends at web's agent, bound to the client's own session and the same QUIC key | holds |
| 23 | the agent binds a direct connection to a session only for that session's client | holds |
| 24 | the client takes no other machine's certificate on the direct path | holds |
| 25, 26 | witnesses: the client takes a direct connection; the agent binds one | attack (reachable) |
| 27 | injective agreement per (session, epoch): the agent attaches a stream at epoch e only on the client's OPEN for e | holds (lane DIRECTPATH2, gap G2; mutant `token-no-epoch`) |
| 28 | what the client sends on a re-attached relayed stream stays secret | holds, also under `token-no-epoch`: a replay is a denial only |
| 29 | witness: the agent attaches a relayed re-attach | attack (reachable) |
| 30 | what the group-dial client sends for `pg@db` reaches no one outside group db | holds (lane SVCBIND; mutant `group-dial-no-group-check`) |
| 31 | ... and only a service its machine publishes under db: not web's `vault`, not mal's `pg` published under ops | holds (mutants `agent-no-alpn-check`, `agent-no-publish-check`, `client-no-alpn-check`) |
| 32 | injective agreement for the group dial: the answer it takes, an agent sent in that session | holds (mutant `group-dial-no-group-check`) |
| 33 | a machine dial reaches only the named agent's named service: the relay cannot route `web/pg` to web's `vault` | holds (mutants `client-no-alpn-check`, `agent-no-alpn-check`) |
| 34, 35 | witnesses: the group dial completes; web's second service serves | attack (reachable) |
| 36 | a direct connection a client takes names its session's machine: the relay cannot move a group dial's session to another instance | holds (lane DIRECTGROUP; mutant `group-direct-no-name-check` with `direct-no-token`; every `direct-no-cert-check` line) |
| 37 | witness: a group dial's session goes direct | attack (reachable) |
| 38 | a datagram a client sends on a direct connection it took (a QUIC DATAGRAM frame) reaches only web's agent | holds (lane UDP1, design; fails where a machine dial's 21 does: `direct-no-cert-check`) |
| 39 | the agent hands a datagram to session k only if k's own client sent it, on a connection bound to k (not injective: a replayed packet is QUIC's to discard) | holds (mutant `dgram-tag-unbound`; fails where 23 does, and with `direct-no-cert-check`: the direct key leaks) |
| 40, 41 | witnesses: a client sends a datagram direct; the agent hands one on | attack (reachable) |
| 42 | what reaches a service of a kind was dialled with that kind: the relay cannot route a stream client to the datagram service of the same name, or the reverse | holds (mutants `agent-ignores-kind`, `client-no-alpn-check`, `agent-no-alpn-check`; fails where 7 does) |
| 43 | witness: the datagram client reaches the datagram service | attack (reachable) |

A TLS record is bound to its place in its direction's stream (TLS 1.3's
sequence number in the AEAD nonce): the model's close record names the
bytes it follows. Without that binding the model finds the attacker
splicing one agent session's close record onto a replay of the client's
handshake to another; TLS's sequence numbers and the server's random
rule it out, and the model does not re-prove TLS.

Mutants, each check its own, the client's and the service's apart:
`client-no-chain-check` (a certificate the relay made), `no-name-check`
(another machine's), `client-no-expiry-check`, `client-no-crl-check`;
`agent-no-chain-check`, `no-group-check`, `agent-no-expiry-check`,
`agent-no-crl-check`, `skip-certificate-verify`. No downgrade: a client or
service is in one mode, set by its own configuration (nfltr: an enrolled
machine's client is in organisation mode; `--plain` per call), never by
the relay's word, and never falls back. `downgrade-plain` (the client sends
in plain when the relay answers that the service is plain) fails 1;
`downgrade-any-client` (the service serves a client without an
organisation certificate) fails 6 and 7. The target: `relay-names-target`
(an agent without a target of its own dials the open's, E2EEPROOF finding
1 before its fix; today `ErrE2EENoFixedTarget` at `New`) and
`relay-names-target-with-forward` fail 1. `agreement-without-key-check`
(a response taken without the session key) fails 2. The ends: `clear-end`,
`agent-clear-end`, `abort-as-close`, `client-abort-as-close` (above).

Direct paths (queries 21-26; lane DIRECTPATH, nfltr
`docs/decisions/direct-paths-2026-11-11.md`; a design checked before any
code). Once the session's TLS is up, its client may move the session's
bytes, the same TLS records under the same key, to a direct QUIC
connection to an address the relay hands it (a candidate, a QAD reply):
the attacker decides who answers there. The client takes the direct
connection only if the answer's certificate passes the session's own
check (chain, name, NotAfter, CRL) and both ends prove the session: each
sends, inside the QUIC session, an exporter of the TLS session bound to
the QUIC key and to its role (`tokC`, `tokS`); the agent binds a direct
connection to a session only on that session's client token. Mutants:
`direct-no-cert-check` (whoever answers: 21, 24; with `direct-no-token`
too, 22), `direct-no-token` (the agent's token unchecked at the client:
22), `token-unbound` (tokens without the QUIC key: alone the certificate
check holds; with `direct-no-cert-check`, a relay in the middle with two
QUIC keys fails 21-24), `token-no-role` (one token both ways: reflected,
22), `agent-direct-no-token` (bound on the relay's word: 23). The agent's
checks of the session's client guard 23 as well: a client it admits
wrongly holds the session key. The model's `BIND:direct.*` ids get their
refusal rows in the code's bindings test when the code lands. The
cut-over's byte order (none lost, duplicated or reordered) is link's
`spec/DirectPath.tla`, not here.

Re-attach (queries 27-29; lane DIRECTPATH2, gap G2 of the direct-paths
doc). Each attach is a fresh stream, an epoch, opened by the client with
`OPEN(epoch, token)`: ep1 the direct connection, ep2 and ep3 relayed
streams after a fallback. Every token binds its epoch
(`BIND:direct.epoch`); a relayed one is an exporter of the session's TLS
(here `h((k, ns))`, with the server's random `ns`, as TLS 1.3's exporter
takes the whole transcript; without it the relay replaying the client's
handshake to a second agent session would give two sessions one
exporter), the client's role and the epoch. The relay sees a relayed
OPEN and can replay it on a new stream with another epoch; the agent, one
acceptor per epoch of a session, attaches only on the token for that
epoch. `token-no-epoch` (no epoch in the token) lets ep2's OPEN attach
ep3 (27 fails) while the bytes on it stay the session's records under its
key (28 holds): the replay is a denial only. A client mutant that takes
the relay's certificate gives it the key, and so the re-attached bytes
(28); an agent mutant that admits the relay's own client lets it attach
its own session (27).

Services by name (queries 30-35; lane SVCBIND, nfltr
`docs/decisions/service-discovery-2026-11-12.md` section 4). The machine
certificate names the machine, which every agent and service on it share,
so the name check alone lets a relay route `web/pg` to web's `vault`, and,
with discovery, `pg@db` to any service of any db machine. The model adds
web's second service `vault` (published under no group), machine `mal`
(group db, live; its `pg` published under ops, not db), and a group-dial
client beside the machine-dial ones; web's certificate is in group db. A
client offers one ALPN protocol naming what it dialled, `alpnM(agent,
service)` (`nfltr-svc/<agent>/<service>`) or `alpnG(service, group)`
(`nfltr-svc/<service>@<group>`); the model sends the offer in the clear
(it does not lean on the transcript covering the ClientHello) and the
agent's choice back in EncryptedExtensions under the session key. The
agent accepts an offer only for the service the session was routed to,
and for a group only one it publishes that service under and its
certificate's OU holds, else the handshake ends (`no_application_protocol`);
the client requires the negotiated protocol to equal its offer. The
group-dial client checks the chain, OU contains the group, NotAfter and
the CRL, and no name. The key exchange is bound to the server's random (as
TLS 1.3's key schedule takes the transcript): without it the relay replays
a client's handshake to a second agent session of the same machine, web's
`vault`, which then reads the session; queries 1-29 keep their results
with or without it. Mutants: `client-no-alpn-check` (the negotiated
protocol ignored: the relay rewrites the offer, 31, 33), `agent-no-alpn-check`
(any offer taken: the open names the service, 31, 33),
`group-dial-no-group-check` (any organisation machine, eve: 30, 32),
`agent-no-publish-check` (`<s>@<g>` served for a service not published
under g, mal's `pg`: 31). Bindings `BIND:org.service`, `BIND:org.group`,
`BIND:org.publish`. Not modelled: two agents on one machine (the ALPN
names the agent; the model's agent is its machine).

Direct paths under a group dial (queries 36-37; lane DIRECTGROUP, nfltr
`docs/decisions/service-discovery-2026-11-12.md` section 4 "Direct paths
under a group dial"). The group-dial client runs the direct path too; with
no machine named, its direct check takes the name its session's
certificate carries (the machine-dial client's, the name it dialled). 36:
a direct connection any client takes names its session's machine, so the
relay cannot move a group dial's session to another instance of the
group. Mutant `group-direct-no-name-check` (the group's check on the
direct answer, any db machine): alone it holds (the tokens bind the
session: another instance holds no token for it); with `direct-no-token`
the relay hands the client mal's certificate and the client takes it (36).
`group-dial-no-group-check` now also gives the relay the direct path (21,
22, 24): the session's machine is eve, so is the direct answer. Which agent
the control exchange and a re-attach reach is the relay's routing, as the
candidates already are: a wrong one is a denial. Not modelled, as above:
two agents on one machine serving one `<s>@<g>` (the tokens refuse the
other's direct answer).

Datagram services (queries 38-43; lane UDP1, nfltr
`docs/decisions/nf1-udp-2026-11-14.md` section 3; design, no code yet). A
service has a kind, stream or datagram, and one name may serve both (dns
over tcp and udp): web serves `pg` as a stream and as a datagram service,
both published under db, and another machine-dial client dials web's
datagram `pg`. The ALPN carries the kind, the prefix `nfltr-svc/` for a
stream and `nfltr-dg/` for a datagram service in both dial forms
(`alpnM(kind, agent, service)`, `alpnG(kind, service, group)`); the agent
accepts an offer only of its service's kind (`BIND:org.kind`, its row
pending lane UDP2), and the client's existing check of the negotiated
protocol (`BIND:org.service`) carries the kind back. Mutant
`agent-ignores-kind` (the agent takes an offer of either kind: the relay
routes the stream client to the datagram `pg`) fails 42 alone;
`client-no-alpn-check` now fails 42 too (the relay rewrites the offer's
kind). The attack needs one name under both kinds: with names unique per
agent the service name in the ALPN already refuses it and the prefix is
defence in depth. Once a datagram session is direct, its datagrams ride the direct
connection as QUIC DATAGRAM frames under its keys, tagged with the attach,
and the agent hands one to a session only on a connection bound to it
(`BIND:dgram.tag`, as `cap_address.pv` 21-24): `dgram-tag-unbound` (the
agent accepts a datagram on any direct connection it accepted, before the
client's token) fails 39 alone. Every earlier query keeps its result under
every mutant. The flows inside the association are `spec/DatagramAssoc.tla`.

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

### cap_address.pv: the capability address nf1 (lane NF1PV; codec `client/capaddr`, lane NF1CODEC)

A server publishes one service under an address; whoever holds it reaches
that service end to end encrypted, with no account and no certificate of
their own (nfltr `docs/decisions/cli-cat-2026-11-12.md` section 5). The
client knows only the address `A = (R, rid, pin, sec)`. The model fixes the
message flow the address codec and its clients and servers implement:

| field or message | what it is | what it binds |
|---|---|---|
| `R` | the relay host the server registered at | the client opens there and nowhere else (not a saved relay, `--server` or a redirect) |
| `rid` | the rendezvous id: 16 random bytes, independent of the key and the secret | what the relay routes by; the only field of the address a relay learns |
| `sec` | the secret: 32 random bytes, always present (no empty or absent secret in the format; the codec refuses all zeros) | admission: only its holders are served |
| `pin` | `H("nf1-pin", sec, pk)`: the server's TLS key, keyed by the secret | the key the client accepts, and unlinkability: a relay that sees `pk` cannot compute it |
| encoding | `nf1` + a checksummed encoding of a version and the four fields | parsed offline; a bad checksum or a missing field is exit 1 |
| 1. REGISTER (server -> R, on its agent session) | `rid`, `pk`, `rec = Sign_sk("nf1-rdv", R, rid, hints)` | `hints` is whatever a client acts on before TLS (direct candidates) |
| 2. OPEN (client -> R) | `rid`, end to end encrypted | no plain mode: an answer "plain" is refused |
| 3. rendezvous answer (R -> client) | `(pk, rec)` | the client requires `pinOf(sec, pk) = pin` and `rec` a signature under that `pk` over the tag, the relay it opened at, its `rid` and `hints`, before it uses `hints` or opens TLS |
| 4. TLS 1.3 through the relay's stream | the server's certificate must carry exactly that `pk`; the client presents none | |
| 5. PROOF (the client's first record inside TLS) | `H("nf1-proof", sec, exporter)` | the exporter covers the handshake transcript, the server's certificate included; the server checks it with the secret of the address the session was routed to (`rid`'s acceptor), never another address it serves under the same key, and closes the session otherwise; nothing of the service runs before |
| 6. the service | its bytes both ways under the TLS key | |

The codec (`client/capaddr`): the text is `nf1` + base32 (RFC 4648
alphabet, lowercase, no padding) of `version (1) | len(R) | R | rid | pin |
sec | CRC-32C` of the bytes before it; only the canonical text parses. The
pin and the proof are HMAC-SHA256 keyed by `sec` over the model's tag and
the key's DER SubjectPublicKeyInfo (`nf1-pin`) or the TLS exporter
(`nf1-proof`, label `EXPORTER-nf1-proof`, 32 bytes); the record is Ed25519
over `nf1-rdv | len(R) | R | rid | hints`. Vectors:
`client/capaddr/testdata/vectors.json`.

The wire (lane NF1RDV, package `client/nf1`; nfltr
`docs/decisions/nf1-rendezvous-2026-11-13.md`): REGISTER is the service's
declaration on the agent's session (`agentservices` `;nf1=<rid hex>`), so
the relay gets `rid` at registration and `pk`, `rec` only on an open, which
the model's attacker can make (it knows `rid`); the answer is the agent's
first bytes in the routed session (`"nf1a"` and three length-prefixed
fields), which every relay on the way may replace, as in the model; after
`Admit` the server sends one verdict byte inside the pinned TLS. The model
is unchanged: each step gives the attacker no more than the model's.

The attacker owns every relay, answers every open, opens sessions of its
own to any `rid`, and holds a second address (A2) of the same server and
key. TLS 1.3 as in `e2ee_tcp.pv`; the exporter is `h((k, ns, pk))`
(RFC 8446 7.5: the exporter secret derives from the transcript).

| # | query | result | fails under mutant |
|---|---|---|---|
| 1 | secrecy of what A1's client sends | T | `client-no-pin-check`, `rendezvous-any-key`, `downgrade-plain` |
| 2 | secrecy of what A1's service answers (only holders of `sec1` admitted, the holder of A2 included) | T | `server-no-secret-check`, `address-secret-optional`, `server-any-secret`, `client-no-pin-check` with `proof-unbound` |
| 3 | what A1's acceptor takes was sent once by A1's client in that session | T | as 2 |
| 4 | what the client of `rid` takes was sent once, in that session, by `rid`'s acceptor: injective agreement on the service | T | `client-no-pin-check`, `rendezvous-any-key`, `server-no-secret-check`, `server-any-secret` |
| 5 | the client's TLS session ends only at the pinned key | T | `client-no-pin-check`, `rendezvous-any-key` |
| 6 | A1's acceptor admits only a session whose client proved `sec1` | T | as 2 |
| 7 | the rendezvous answer the client takes is the server's registration (key, `rid`, `hints`) | T | `rendezvous-any-key` |
| 8 | a session the client completes went through the relay the server registered `rid` at | T | `relay-substitutes-relay`, `rendezvous-any-key` |
| 9 | the client never sends in plain | T | `downgrade-plain` |
| 10 | the attacker, which sees `rid1`, the key, the registration and every session and holds A2, cannot produce A1's pin | T | `pin-unkeyed`, `address-secret-optional` |
| 11-14 | witnesses: the client takes the answer; A1's acceptor admits it; A1's service gets its bytes; the client gets the answer | F (reachable) | |
| 15 | what A1's client sends on a direct connection it took reaches only A1's server, wherever the relay routed the punch | T | `client-no-pin-check`, `rendezvous-any-key`, `direct-no-pin-check` with `nf1-token-unbound` |
| 16 | the client's direct handshake ends only at the pinned key | T | `direct-no-pin-check`, `client-no-pin-check`, `rendezvous-any-key` |
| 17 | a direct connection the client takes is bound, once, by A1's agent to the client's own session | T | `nf1-direct-no-token`, `direct-no-pin-check` with `nf1-token-unbound`, `server-any-secret`, `server-no-secret-check` |
| 18 | A1's agent binds a direct connection only for the session's own client | T | `nf1-agent-no-token`, the secret-check mutants |
| 19, 20 | witnesses: the client takes a direct connection; A1's agent binds one | F (reachable) | |
| 21 | a datagram A1's client sends on a direct connection (a QUIC DATAGRAM frame) reaches only A1's server | T | as 15 |
| 22 | A1's agent hands a datagram to session k only if k's own client sent it, on a connection bound to k (not injective: a replayed packet is QUIC's to discard) | T | `dgram-tag-unbound`, `nf1-agent-no-token`, the secret-check mutants |
| 23, 24 | witnesses: the client sends a datagram direct; A1's agent hands one on | F (reachable) | |
| 25 | a client takes an answer for its dial's kind (stream, datagram) only if the server registered the address with that kind | T | `client-no-kind-check`, `hint-unbound-u1`, `hint-unbound`, `rendezvous-any-key` |
| 26 | witness: a datagram client takes A1's answer | F (reachable) | |

Direct paths (lane NF1DIRECT, nfltr `docs/decisions/nf1-direct-2026-11-14.md`):
the record's `hints` carry one fact, `d1` (the listener takes direct
paths), which the client acts on (it frames its session) only once the
record covers it; the candidates travel inside the session's TLS. After
admission the session may move to a direct QUIC connection (link
pathswitch under the session's TLS, the organisation's mechanism of
`e2ee_tcp.pv` 21-26): the client takes it only from the pinned key
(`BIND:nf1direct.pin`) and with the agent's token, the agent binds it to a
session only on that session's client token; the tokens are keyed by the
session's exporter and bind the direct connection's exporter, which covers
its handshake's key. Mutants: `hint-unbound` (hints taken from the frame,
not the record: fails 7, and the kind's 25), `direct-no-pin-check` (16; with
`nf1-token-unbound` 15-18), `nf1-token-unbound` (holds alone),
`nf1-direct-no-token` (17), `nf1-agent-no-token` (18).

Datagrams (lane NF1UDP, nfltr `docs/decisions/nf1-udp-2026-11-14.md`;
design, no code yet): once a session is bound to a direct connection, its
datagrams may ride that connection as QUIC DATAGRAM frames under the
connection's keys, tagged with the attach (the attach stream's id); the
agent hands a frame to a session only under a tag of a session attached
on that connection (`BIND:dgram.tag`, its row pending the code lane).
Mutant `dgram-tag-unbound` (the agent accepts a datagram on any direct
connection it accepted, bound or not): fails 22 alone. The flows inside
the session, the tag's lifetime across associations and the revocation
are the relay's `spec/DatagramAssoc.tla`.

The kind (lane UDP1, queries 25-26; design, no code yet): the hints are a
flag list (`d1`, `u1`, `d1,u1`), modelled as the pair (direct, kind); `u1`
says the address serves datagrams. A1 is a datagram service, A2 a stream
service, and A1 has two clients, one dialling each kind (`cat forward
--udp` or not). A client takes an answer only when the record's kind is
its dial's (`BIND:cap.kind`, its row pending lane UDP2), so a relay cannot
make a stream client speak to a datagram service or the reverse. Mutants:
`client-no-kind-check` (the dial's kind not compared) and
`hint-unbound-u1` (the kind taken from the answer frame's hints, `d1`
still from the record) each fail 25 alone; 1-24 keep their results under
every mutant.

`cap_address_link.pv` states 10 as an observational equivalence: two
servers register `rid1` and `rid2`, the attacker reads both registrations,
opens TLS sessions to both and is handed one pin (rid1's on the left,
rid2's on the right); it cannot tell which (T). Under `pin-unkeyed` it
hashes each registration's key (`?`: ProVerif's answer for a broken
diff-equivalence; the derivation is in its log).

Mutants: `client-no-pin-check` (the TLS certificate's key not compared),
`rendezvous-any-key` (the answer's key not compared to the pin),
`relay-substitutes-relay` (the client opens at another relay than its
address's), `server-no-secret-check`, `address-secret-optional` (the
format lets the secret be empty: A1 has none), `server-any-secret` (an
acceptor takes a proof under any of its key's secrets and serves its own
service: a client of A1 routed to A2's acceptor, and the holder of A2 into
A1), `pin-unkeyed` (`pin = H(pk)`: the relay reads `pk` in every
registration and TLS handshake, so it links `rid` to the pin),
`downgrade-plain`, `proof-unbound` (the proof without the exporter: caught
only with `client-no-pin-check`, where a fooled client's proof opens the
real server; with the exporter it does not, 2, 3 and 6 hold).

Not covered: an active relay sees `pk` (TLS shows the certificate to
whoever opens a session), so the rendezvous ids of addresses that share a
key link to each other; addresses that must not link use a key each. A
leaked address is a capability: revoking it is stopping the server (no
rotation, no relay state across opens: nfltr's cli-cat decision, "TLA+:
none").

### First use

| path | what the first contact trusts |
|---|---|
| TCP (organisation mode) | nothing on first contact: both ends hold the organisation's root from their enrolment; never the relay's word |
| `nfltr shell` | organisation mode since nfltr lane ORGCUT: the host certificate under the organisation's root (nfltr's model) |
| WireGuard unpaired | the relay, on every connect; paired: the pairing file, copied out of band |
| P2P unpaired | the relay, unless the users compare the fingerprints; paired: the pairing file |

### Environment assumptions of these paths

| assumption | source |
|---|---|
| TLS 1.3 with a checked server key is an authenticated channel; no resumption skips the certificate check | Cremers et al., IEEE S&P 2017; Bhargavan et al., IEEE S&P 2017; organisation TLS (`orgServerConfig`) disables session tickets |
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
| e2ee_tcp.pv | client/agent/session_plan.go |
| e2ee_tcp.pv | client/agent/agent.go |
| e2ee_tcp.pv | client/agent/services.go |
| e2ee_tcp.pv | client/agent/org.go |
| e2ee_tcp.pv | client/agent/testdata/org_mutants.txt |
| e2ee_tcp.pv | client/tlsend/tlsend.go |
| e2ee_tcp.pv | client/agent/direct.go |
| e2ee_tcp.pv | client/agent/direct_server.go |
| e2ee_tcp.pv | client/agent/direct_client.go |
| e2ee_tcp.pv | client/agent/direct_bindings_test.go |
| e2ee_tcp.pv | client/agent/service_alpn.go |
| e2ee_tcp.pv | client/agent/service_bindings_test.go |
| e2ee_tcp.pv | client/orgid/verify.go |
| e2ee_tcp.pv | client/orgid/identity.go |
| e2ee_tcp.pv | client/orgid/follow.go |
| e2ee_tcp.pv | client/orgid/group_dial_bindings_test.go |
| e2ee_tcp.pv | client/orgid/testdata/mutants.txt |
| e2ee_tcp.pv | client/nfnet/org.go |
| e2ee_tcp.pv | client/nfnet/dial_bindings_test.go |
| wg_exit.pv | client/wg/keys.go |
| wg_exit.pv | client/wg/tunnel.go |
| wg_exit.pv | client/agent/wgexit/wgexit.go |
| wg_exit.pv | proto/wire/wgwire/wgwire.go |
| cap_address.pv | client/capaddr/capaddr.go |
| cap_address.pv | client/capaddr/capaddr_bindings_test.go |
| cap_address.pv | client/nf1/nf1.go |
| cap_address.pv | client/nf1/dial.go |
| cap_address.pv | client/nfnet/nf1.go |
| cap_address.pv | client/agent/direct_nf1.go |
| cap_address.pv | client/agent/direct_nf1_bindings_test.go |
| p2p_e2e.pv | client/p2p/e2e.go |
| p2p_e2e.pv | client/p2p/rtcdata.go |
