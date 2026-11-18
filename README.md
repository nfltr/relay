<p align="center"><img src="docs/logo.svg" width="96" alt="relay"></p>

# nfltr relay client SDK and protocol

Go modules for talking to an nfltr relay: the client SDK and the wire
protocol it speaks. The hosted relay runs at **nfltr.xyz**
(`grpc.nfltr.xyz:443` for agents, `https://nfltr.xyz` for HTTP); the `nfltr`
CLI is built on these modules.

It is for Go developers who write agents, clients and tools for an nfltr
relay. **Status:** the modules are pre-1.0 and versioned on their own
(the newest `proto/vX.Y.Z`, `client/vX.Y.Z` and `org/vX.Y.Z` on the
[tags page](https://github.com/nfltr/relay/tags)). **In the nfltr stack:**
[nfltr/link](https://github.com/nfltr/link) (the multiplexing layer, its
`peerlink` carries the agent link) → this repository (SDK and protocol) →
nfltr-relay (the relay, which
implements the protocol) → [nfltr](https://nfltr.xyz) (the CLI and product,
which uses the SDK). **Docs:** this file, [CONTRIBUTING.md](CONTRIBUTING.md),
[nfltr.xyz/docs](https://nfltr.xyz/docs).

| Module | Import path | What it holds |
|---|---|---|
| [`proto/`](proto) | `github.com/nfltr/relay/proto` | the v1 protos (`nfltr.relay.v1`, `nfltr.blob.v1`, `nfltr.mailbox.v1`, `nfltr.presence.v1`) with their generated Go, `pb` (the agent wire: the `rpcserver.Dispatcher` gRPC service agents and clients connect over), and `wire/*`: the hand-written codecs both ends speak (agent-wire metadata, data plane, WebSocket frames, blob headers) |
| [`client/`](client) | `github.com/nfltr/relay/client` | the SDK: `agent` (expose a local HTTP service through the relay), `rpcclient` (agent-to-agent calls), `grpcclient` (dialing, mTLS), `p2p`, `relayblob`, `mailboxclient`, `presenceclient`, `relayoutage`, `relaytrust`, `machinecert` (a machine's key, CSR and certificate renewal, the certificate files nfltr saves and the credential that presents and renews them; `machinecerttest` saves a test pair), `orgid` (an organisation machine's identity: the checks of a peer's certificate, name, groups and the issuer's CRL, and following the CRL) |
| [`org/`](org) | `github.com/nfltr/relay/org` | an organisation's own certificate authority for its machines, which runs on the owner's machine, never on the relay (the relay only carries its mailboxes): `orgpki` (the x509 profile, single-use tokens, enrolment, renewal, revocation, CRLs, the hash-chained audit log, root rotation, SSH host certificates, moving the issuer; an app's device for a person by an admin code or by the person's OpenID Connect sign-in, verified with go-oidc), `orgissuer` (the issuer's directory), `orgmachine` (an enrolled machine's directory), `orgenrol` (enrolment and renewal over the relay's mailboxes). Its models: `spec/enrol/`, `spec/orgmove/`, `spec/appenrol/`, `spec/proverif/enrol.pv`, `orgmove.pv` and `app_enrol.pv`; an app's sign-in (code + PKCE) is the client's `appenrol.SignIn`. What it issues `client/orgid` checks |

The modules are versioned on their own: tags `proto/vX.Y.Z`,
`client/vX.Y.Z` and `org/vX.Y.Z`.

## Quick start: expose a local service

You need a machine certificate for the relay: `nfltr config login` enrols
this machine (or enrol from code with `client/machinecert`). Below,
`machine` is that certificate as a `tls.Certificate`.

```sh
go get github.com/nfltr/relay/client@latest
```

```go
package main

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/nfltr/relay/client/agent"
)

func main() {
	a := agent.New(agent.Config{
		ServerAddr: "grpc.nfltr.xyz:443",
		AgentID:    "my-service-01",
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{machine}},
		Routes:     []agent.Route{{Backend: "http://localhost:8080"}},
	})
	if err := a.Connect(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Println("tunneling as", a.AgentID())
	<-a.Done()
}
```

The agent reconnects on its own when the relay restarts or the network
drops. It redials, with a bounded, jittered backoff, on every error but a
closed fatal list, and `Done()` closes only then or when the context is
cancelled: the relay refusing the credential (`Unauthenticated`,
`PermissionDenied`), a client or relay too old (`FailedPrecondition` carrying
`agentwire.ClientGenerationTooOld` / `RelayTooOld`), a rejected request
(`InvalidArgument`), or the session replaced by another process with the same
agent ID. `Err()` then says what to do. `rpcclient.FatalClass(err)` is that
list, classified by gRPC code and typed errors, never by message text; use it
in your own reconnect loops. Another program on the same account can then call it through the relay
with `rpcclient`.

To serve an `http.Handler` of the same program instead of a separate
backend, `agent.Listen` connects the agent and returns a `net.Listener`:

```go
ln, err := agent.Listen(ctx, agent.Config{
	ServerAddr: "grpc.nfltr.xyz:443",
	AgentID:    "my-service-01",
	TLSConfig:  &tls.Config{Certificates: []tls.Certificate{machine}},
})
if err != nil {
	log.Fatal(err)
}
log.Fatal(http.Serve(ln, handler))
```

## Compatibility

The protocol is additive within a major version. A relay advertises its
features (`x-nfltr-relay-features` and `GET /api/v1/relay/info`); a client
asks for the features it needs and fails closed, naming the missing feature,
when the relay lacks one.

## Development

```sh
make ci                         # everything the CI workflow runs, read from it (the gate; GitHub Actions is not)
make build vet test test-race   # both modules (go.work joins them)
make fuzz-short                 # every fuzz target, FUZZTIME each (default 10s)
make proto-gen                  # regenerate proto/nfltr/** and proto/pb (needs buf, protoc and the protoc-gen-* plugins)
make proto-report               # buf lint + breaking of proto/pb vs PROTO_BASELINE (report only)
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

A TLC run, ProVerif model or Go mutant list whose inputs did not change is not checked again:
`scripts/cicache.sh` keys each by the sha256 of what it reads (config,
models, jars, arguments; a Go list its package and in-repository dependencies) and replays a stored pass (`CICACHE=off`
disables it, `CICACHE_VERIFY=1` reruns every hit and fails on a different
verdict; `make test-cicache` is its soundness test).

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
