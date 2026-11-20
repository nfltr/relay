# relay v1 API review: proto, client, org

Lane RELAYAPI, 2026-11-20, on relay main `0424e43` (proto v0.21.5,
client v0.23.12, org v0.1.17 the latest tags). The next layer up from
link's review (github.com/nfltr/link `docs/v1-api-review.md`, lanes
LINKAPI and LINKV013), by the same method: every exported identifier of
the three modules, with the questions

- does a consumer need it (relay-core, relay-server, nfltr, send, pipe,
  orch at their mains; a sibling relay module counts, the identifier's
  own module does not),
- is it named well and do its docs name only what exists,
- are its failures documented,
- is it safe to misuse (zero value, a second Close, concurrent use),

and, for the wire, whether every removed proto field is reserved, no
field number was reused and every enum value is documented.

Outcome: 14 exports unexported and 4 deleted (none had a consumer), 48
doc references to names that do not exist fixed and guarded in each
module, a second Close documented and guarded for the datagram API,
`make check-api` added (records below), 0 wire changes. No consumer
changes: relay-core, relay-server, send and pipe (`go vet ./...`) and
nfltr (`go vet` of its 32 packages that import relay) pass against the
branch with `replace` directives. One large deletion is proposed, not
made: `client/p2p`'s file transfer, chat and call surface (155
functions no consumer reaches; it carries a TLA+ spec and a ProVerif
model, so its removal is a lane of its own, below).

## Method

- Uses resolved by type: a small `golang.org/x/tools/go/packages`
  program loads every package and test of a consumer, takes each
  identifier's `types.Object` from `TypesInfo.Uses` and maps it to the
  relay package-level name, method or field it is (so a method called
  on a value of a relay type counts; an implicit use through an
  interface does not, see "Kept"). Consumers at their mains: relay-core
  `4bee3c6`, relay-server `6cf06e3`, nfltr `57786a6`, send `7b6c86a`,
  pipe `e39832e`, orch `ef07310` (orch pins client v0.23.4, the others
  v0.23.12). Each relay module's
  uses of its siblings count; uses inside the identifier's own package
  do not.
- Reachability: `deadcode` (x/tools v0.51.0) over every `main` package
  of each consumer, without tests; a function is dead when every
  consumer that links its package leaves it unreached.
- Each export falls in one of three classes (counts of hand-written
  names: package-level names plus methods and fields; protoc's generated
  code is reviewed through its .proto files instead):

| module | names | used by a consumer | used only by another package of its module | used by nothing outside its package |
|---|---|---|---|---|
| proto (`wire/...`) | 308 | 247 | 0 | 61 |
| client | 1169 | 643 | 136 | 390 |
| org | 344 | 183 | 74 | 87 |

The tables and tools are in the lane's evidence
(`~/nfltr-evidence/relayapi-2026-11-20/`: `uses/class.tsv`, one row per
name with its class and in-module users; `deadall.txt`; the scanner
`main.go`).

## Wire (proto)

| check | result |
|---|---|
| `proto/pb/service.proto` (the agent wire) against every proto tag (45, `buf breaking`, WIRE_JSON) and every version of `pkg/pb/service.proto` in nfltr's history before the split | no field deleted without its number and name reserved, no number reused, no type change. Messages and RPCs that went (`FleetInvoke`, `FulfillArtifact`, `PeerInfo`, `RelayTunnel`, `RelayTCPTunnel`) took their fields with them; the `ophid` fields were renamed to `agent_id` at the same numbers (2026-03, JSON names only: the agent wire is binary) |
| the v1 protos (`proto/nfltr/**`) against every tag that has them | `nfltr/blob/v1` deleted (lane BLOBDEL, with its service: a relay without blobs serves no such RPC); `ErrorReason` 4, 5, 15, 24, 25 deleted and reserved by number and name; `SenderKind` 1 renamed `SENDER_KIND_API_KEY` to `SENDER_KIND_MACHINE` (lane L4S3, the API key cut: stored envelopes keep the number, the proto comment says so; its JSON name changed) |
| enum values documented | `buf lint` COMMENTS clean for the v1 protos. `pb`: `Move`'s four values are documented in the enum's table comment, 29 fields by trailing comments; `buf`'s COMMENTS rules want leading ones (style only, not changed) |
| wire bytes | unchanged in this lane |

Decision: no wire change. For the v1 tag, `proto-report` (report only,
against `proto/v0.2.0`) should become a gate against the latest tag
(`PROTO_REPORT_STRICT=1`, buf on the CI runner): today a deleted field
without `reserved` in `pb` would land unnoticed.

## Findings by module

### proto (`wire/...`)

| identifier | problem | decision | consumers affected |
|---|---|---|---|
| `chunking.AcksUploads` | no caller anywhere (nfltr's relay-core decision doc already said so) | deleted | none |
| `chunking.ReadChunksStreamingWithContext` | unreachable; the agent streams with `ReadUpgradeChunksWithContext`, and `ReadChunksWithContext`'s doc pointed at the dead one | deleted with its five tests; the doc names `ReadUpgradeChunksWithContext` | none |
| `dataplane.CheckExclude`, `ParseWindow`; `turnwire.ValidateTURNURL`; `wsframe.Mask`, `ReadHeader` | used only inside their package (`OpenHeader`/`ParseOpenHeader` check the exclude list; `wsframe`'s reader masks and reads headers) | unexported; the docs that named `CheckExclude` say what is checked | none |
| docs | `dataplane.MaxExclude` named `pb.TCPData.exclude` (the field is `Exclude`), `grpccodec.Pool` and `agentservices.RIDOf` named unexported helpers | fixed | none |

Kept although unused outside their package: the `chunking`,
`agentwire`, `agentservices` and `hookwire` constants (header keys,
liveness presets, bounds a peer must respect: wire values a relay of
another build reads), `a2ahttp`'s `Request`/`Response` fields (the JSON
of an A2A HTTP call), the `wsframe` close codes and `Header` fields, the
sentinels (`ErrRefused`, `ErrTooLarge`, `ErrUploadWindow`,
`ErrMalformed`).

### client

| identifier | problem | decision | consumers affected |
|---|---|---|---|
| `rpcclient.OutgoingMetadata`, `NewOutgoingMetadata` | a metadata builder no code calls | deleted (`outgoing_metadata.go`) | none |
| `agent.SpliceUpgrade`, `UpgradeVisitor`, `SplitRoute`, `TargetURL` | the HTTP tunnel's internals, exported | unexported | none |
| `grpcclient.DialThrough`, `ExplainTLS` | used only by `grpcclient`'s own dial | unexported | none |
| `machinecert.RenewAt` | used only by `Loop.Run`, whose doc now states the schedule | unexported | none |
| 35 doc comments | named unexported helpers or members that do not exist: `holdAdmission`, `tcpStreamGrowth`, `processStream`, `queuePipeWindow`, `dropTarget`/`joinTarget`/`resetTarget`, `DirectEndpoint.punch`, `redialRecheck`, `relayReconnectParams`, `agentHeartbeatInterval`, `a2aE2EERole`, `maxAhead`, `writeFrame`/`readFrame`, `pathWebRTC`/`pathRelay`, `pinOf`/`ridOf`, the model's tag names, `pathAndQuery`; `pb.Dispatcher_ConnectHTTP` (generated name is `Dispatcher_ConnectHTTPClient`); `rpcclient`'s package example called its variable `agent`, the name of a sibling package, so `agent.Invoke` read as a function that does not exist | each names what a caller can use or states the value (64 KiB, 250 ms, 15 s, 4096 frames); guarded | none |
| `dgram.Client`, `Server`, `Flow`, `Forwarder`, `Conn` `Close` | what a second Close returns was undocumented | documented: nil, and `net.ErrClosed` for a `Conn` as net.Conn's; `TestCloseTwice` races two Closes under `-race` and checks the third | none |
| `nfnet.Dialer.Close` | second Close undocumented | documented: always nil | none |

Proposed, not changed (each needs its owner's decision; none blocks a
v1 tag that keeps them):

1. **`client/p2p`'s CLI transfer, chat and call surface** (lane
   P2PDEL). nfltr deleted `nfltr p2p` (`91d974491`, 2026-11-13); since
   then no consumer reaches `Connect`, `SendFile`/`ReceiveFile`,
   `SendDir`/`ReceiveDir`, `Chat`, `CallServer`, `E2E`, `SignalConn`,
   `RelayMux`, `RelayConn`, `OpenDataPath`, `GatherCandidates`,
   `DiscoverExternalAddr`, `OpenBrowser` and their helpers: 155
   functions in `e2e.go`, `rtcdata.go`, `relaymux.go`, `sigconn.go`,
   `relay.go`, `connect.go`, `transfer.go`, `localserver.go`, `ws.go`,
   `datapath_tcp.go`, `encrypt.go`, `stun.go`, `trace_*.go`. The live
   part is the browser direct path (`browserpeer.go`, `BrowserDirect`,
   the signal stream messages of `signal.go`). Deleting the rest also
   deletes `spec/SignalConn.tla` and its trace check (spec README
   "Code map" rows for `sigconn.go`, `relaymux.go`, `e2e.go`,
   `trace_on.go`; `scripts/spec.sh traces`), `spec/proverif/p2p_e2e.pv`
   with `TestP2PE2EModelBindings`, and the gosec baseline rows for those
   files; `rtcdata.go`'s data-channel code the browser path reuses must
   be split from the transfer's first (BP3 reuses it). Gate:
   `make spec spec-mutants spec-bindings spec-proverif`, `go test -race
   ./p2p/ ./agent/`, the browser e2e.
2. `rpcclient.WithA2AE2EEPairingKeyFile`, `CheckA2AE2EEPairingKeyFile`:
   unreached (nfltr keys A2A E2EE with `WithA2AE2EEKeyring`); an E2EE
   key mode with a model, so its removal updates the A2A model first.
3. `agent.WithACME`, `ACMEConfig`, `Agent.RotateE2EECert`,
   `RotateE2EECertFromFiles`: unreached since nfltr's agents take
   machine certificates; delete with relay-core's SNI E2EE path's
   decision.
4. `machinecert.Client.Rotate`, `RotationProof`: the client half of
   relay-server's key rotation, which no nfltr command calls: wire a
   `nfltr machine` command or delete both halves.
5. `nf1.HandshakeDatagram`: unreached (the datagram dial goes through
   `nfnet`); delete or use.
6. The 136 names used only by another client package (`capaddr`'s
   proof and record functions for `nf1`, `nf1`'s listener plumbing for
   `agent` and `nfnet`, `tlsend`, `pairfile`, ...): candidates for
   `client/internal/`, after v1 only if a third party needs none of
   them; the sentinels among them (`capaddr.Err*`, `nf1.Err*`) reach
   callers wrapped and stay.
7. Safety statements still missing: concurrent use of
   `mailboxclient.Client`, `presenceclient`, `machinecred`,
   `orgid.Identity`; what a second Close of `nfnet.Conn` and
   `tlsend.Conn` returns (it differs: a link session's second end is
   nil, TLS's is the transport's error).

Kept although no consumer at the mains uses them, each for a stated
reason:

- The SDK's documented entry points: `agent.Listen` (package doc,
  `ExampleListen`), `nfnet.Dial` (`ExampleDial`, nfltr
  `docs/decisions/p2p-sdk-2026-11-14.md`), `orgid.DefaultDir`,
  `capaddr.Format` (Parse's inverse).
- Names added since client v0.23.12 for the consumers' next bump
  (CERTPAIR, CERTATOMIC: `machinecert.Pair`, `LoadPair`, `SavePair`,
  `orgid.Pair`, `ReadPair`, `CRLCopy`, `mailboxclient.Client.OrgCRL`,
  `PutOrgCRL`, `OrgCRLPath`, `tlsend.Conn.CloseWriteSyncReceived`,
  package `pairfile`).
- Sentinels the docs tell callers to test (`agent.ErrBacklogFull`,
  `ErrOrgClientRefused`, `ErrServiceNotNegotiated`, `dgram.ErrFlowsFull`,
  `ErrProtocol`, `handoff.ErrEnded`, `machinecred.ErrRenewing`,
  `pairfile.ErrMismatch`, `rpcclient.ErrA2AE2EENoKey`, ...), and the
  values of an exported enumeration a caller switches on (`agent.QAD*`,
  `Reason*`, `Transport*`, `mailboxclient.Sender*`).
- Types that appear in a used function's signature (`agent.Session`,
  `Request`, `Caller`, `dgram.Flow`, `nfnet.Info`, ...): a caller holds
  them without naming them.
- Methods that only satisfy an interface (net.Conn's, net.Listener's,
  `error`'s, `fmt.Stringer`'s, `peerlink.EndNotifier`'s
  `QueueConn.EndDelivered`).
- Fields of option and result structs (`nfnet.Event`, `DialOptions`,
  `ListenOptions`, `dgram.FlowOptions`, `machinecert.Loop`): the
  struct is the API.
- The `*test` helper packages (`idptest`, `machinecerttest`,
  `mailboxtest`, `relaytrusttest`): test doubles for consumers' tests.

### org

| identifier | problem | decision | consumers affected |
|---|---|---|---|
| `orgpki.HostSerial`, `SignCheckpoint` | used only inside `orgpki` | unexported | none |
| 10 doc comments | `serveWait`, `wakeEvery`, `alarmMsg`, `wrongMachine`, `Service.maintain`, `authUntil`, `verifyIDToken`; `orgmachine.Machine.Hold` named "the relay agent's holdAdmission" | the values (10 s, a minute, the logged text), `Service.Run`, the spec file; `Hold` names `orgid.Identity.Hold` | none |

Proposed: `orgmachine.Machine.Hold` and `orgid.Identity.Hold` are the
same loop in two modules (org imports client): org's could call
client's. The app device identity surface (`orgpki.Issuer.AddSignInRule`,
`RemoveSignInRule`, `SignInRules`, `RevokeApp`, `RevokePerson`,
`RenewIssuer`, `NewSignInRequest`, `ValidDomain`,
`orgenrol.JoinSignIn`) has no consumer yet: its nfltr commands are
pending (nfltr `docs/decisions/app-device-identity-2026-11-16.md`);
kept. `orgpki.Entry`'s fields are the audit log's JSON: kept.

## Guards added

| guard | what fails |
|---|---|
| `TestDocsNameNoGhosts` in proto, client and org (`proto/internal/tools/docnames`, stdlib only; link's test generalised: a doc may qualify a sibling module's names) | a doc comment of a public package naming an unexported identifier, a member its type lacks, or a name `api/<module>-*.txt` records as removed (planted `fooBar` in `orgid.Identity.Hold`'s doc: fails) |
| `make check-api` (`scripts/check-api.sh`, link's; a CI step) | an API change since a module's latest tag that `api/<module>-<tag>.txt` does not list |
| `dgram.TestCloseTwice` | a second Close of a datagram type returning other than its doc says |

## What the next releases make (api/)

`api/proto-v0.21.5.txt`, `api/client-v0.23.12.txt`,
`api/org-v0.1.17.txt` list every change since those tags, the ones
already on main (BLOBDEL's deleted blob packages and error reasons,
CERTPAIR's and CERTATOMIC's additions) and this lane's. Both proto and
client remove names, so their next releases are minors: **proto
v0.22.0, client v0.24.0, org v0.2.0**. No consumer at its main uses a
removed name; orch's `go vet` against relay main fails independent of
this lane (it pins relay-core v0.16.3, which names `dataplane.Conn`, gone
since the data connections were retired).

## What "v1 compatible" will mean for relay

| surface | v1 promise | guard |
|---|---|---|
| Go API of `github.com/nfltr/relay/{proto,client,org}` (non-internal packages) | Go 1 compatibility: no exported name removed or changed in v1.x | `make check-api`, `TestDocsNameNoGhosts` |
| the agent wire (`proto/pb`) and the v1 protos | field numbers and names frozen; a removed field reserved; new behaviour behind new fields or metadata keys | `buf breaking` (`proto-report`, to become strict) |
| metadata keys and header values (`agentwire`, `chunking`, `dataplane`, `agentservices`) | names and meanings frozen; new ones additive | each package's tests, relay-core's cross-version smokes |
