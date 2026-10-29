// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc/keepalive"
)

// DialOption configures an Agent during Dial.
type DialOption func(*dialOptions)

// AgentOption configures an Agent created around an existing AgentTunnel.
// These options are applied before receive processing starts.
type AgentOption func(*agentOptions)

type agentOptions struct {
	a2aE2EEInbound bool
	noHeartbeat    bool
}

type dialOptions struct {
	agentID           string
	apiKey            string                      // server-generated API key for agent authentication (preferred)
	a2aE2EE           bool                        // transparently encrypt A2A payloads end to end
	a2aRelayRequests  bool                        // with a2aE2EE: still serve relay-originated plaintext requests
	a2aPairingKeyFile string                      // with a2aE2EE: authenticate handshakes with this pairing key
	labels            map[string]string           // optional fleet labels for this agent
	capabilities      []string                    // optional: advertised capabilities (e.g. "p2p", "ssh", "http")
	tlsEnable         bool                        // enable TLS for the gRPC connection
	clientCert        string                      // client cert file for mTLS
	clientKey         string                      // client key file for mTLS
	caFile            string                      // CA file for mTLS server verification
	heartbeatInterval time.Duration               // optional: heartbeat send interval (0 = use default agentHeartbeatInterval)
	keepalive         *keepalive.ClientParameters // optional: gRPC transport keepalive for long-idle connections
	liveness          agentwire.Liveness          // optional: zero = agentwire.LivenessDefault
}

// WithAgentID sets the agent's AgentID for authentication.
func WithAgentID(agentID string) DialOption {
	return func(o *dialOptions) { o.agentID = agentID }
}

// WithAPIKey provides a server-generated API key for agent authentication.
// This is the preferred auth method. The server derives the agent's AgentID
// from its key store so the agent identity cannot be forged.
// When set, the key is sent as "x-api-key" gRPC metadata. WithAgentID is
// still required for client-side logging/routing but the server-side
// identity comes from the key store.
func WithAPIKey(key string) DialOption {
	return func(o *dialOptions) { o.apiKey = key }
}

// WithA2AE2EE transparently encrypts A2A request and response payloads using
// an in-band X25519 handshake plus AES-256-GCM. Both endpoints must use an
// updated rpcclient that supports the A2A E2EE control frames.
//
// An agent with E2EE on refuses plaintext requests from peers
// (FailedPrecondition naming --e2ee / NFLTR_A2A_E2EE), so a relay cannot
// downgrade a stream or inject one of its own. Streams to the relay's own
// agent (RelayAgentID) are sent plaintext: they end at the relay.
func WithA2AE2EE() DialOption {
	return func(o *dialOptions) { o.a2aE2EE = true }
}

// WithA2AAcceptRelayRequests lets an agent with WithA2AE2EE still serve the
// requests the relay itself originates in plaintext: relay-owned dispatch
// from RelayAgentID and fleet-invoke. The relay sees those
// payloads by construction. Only agents whose contract includes relay-owned
// work (nfltr worker, fleet targets) opt in; hubs and nodes must not, or the
// relay could start work on them by claiming to be its own agent. With a
// pairing key (WithA2AE2EEPairingKeyFile) the relay is treated as hostile
// and relay-originated requests are refused regardless.
func WithA2AAcceptRelayRequests() DialOption {
	return func(o *dialOptions) { o.a2aRelayRequests = true }
}

// WithA2AE2EEPairingKeyFile authenticates every E2EE handshake with a
// pairing key: a file of at least 32 bytes of random secret that only the
// user's machines hold (e.g. `openssl rand -hex 32`). Each end proves it
// holds the key with an HMAC over the transaction and both ephemeral public
// keys, and the key is mixed into the session key, so a relay that swaps
// keys (man in the middle) is refused. Both ends need the same file; Dial
// fails if it cannot be read or E2EE is off. It proves "one of your
// machines", not which one. An empty path sets nothing.
func WithA2AE2EEPairingKeyFile(path string) DialOption {
	return func(o *dialOptions) { o.a2aPairingKeyFile = path }
}

// CheckA2AE2EEPairingKeyFile reports why a pairing key file would fail Dial,
// for callers that must refuse to start rather than retry a Dial that cannot
// succeed.
func CheckA2AE2EEPairingKeyFile(path string) error {
	_, err := LoadA2AE2EEPairingKey(path)
	return err
}

// WithAgentInboundA2AE2EE allows an Agent created with NewAgent to accept
// encrypted incoming A2A streams without enabling encryption for streams it
// initiates. It is intended for routing and control agents serving mixed fleets.
func WithAgentInboundA2AE2EE() AgentOption {
	return func(o *agentOptions) { o.a2aE2EEInbound = true }
}

// WithoutHeartbeat makes an Agent created with NewAgent send no idle
// heartbeats: it starts no heartbeat timer or goroutine at all. It is for
// in-process tunnels whose peer never times the agent out (the relay's own
// agent); over a network the relay ends an agent that stays silent.
func WithoutHeartbeat() AgentOption {
	return func(o *agentOptions) { o.noHeartbeat = true }
}

// WithTLS enables TLS for the gRPC connection to the RPC server.
func WithTLS(enable bool) DialOption {
	return func(o *dialOptions) { o.tlsEnable = enable }
}

// WithClientCert configures mTLS client authentication. When set, the agent
// presents a client certificate to the server during the TLS handshake; a
// relay running the mTLS identity provider (security.mtls) maps it to the
// agent's owner and id by its configured rules, so no API key is needed.
//
// - certFile: path to PEM-encoded client certificate
// - keyFile:  path to PEM-encoded client private key
// - caFile:   path to PEM-encoded CA bundle to verify the server (empty = system pool)
func WithClientCert(certFile, keyFile, caFile string) DialOption {
	return func(o *dialOptions) {
		o.clientCert = certFile
		o.clientKey = keyFile
		o.caFile = caFile
		o.tlsEnable = true // mTLS implies TLS
	}
}

// WithLabels attaches fleet labels to this agent. Labels are sent as the
// "x-agent-labels" gRPC header as a JSON object (values may hold , and =) and stored
// server-side for fleet selector matching. Labels are immutable for the
// lifetime of the connection; to change them reconnect with new values.
//
// Example:
//
//	rpcclient.Dial(ctx, addr,
//	    rpcclient.WithAgentID("sensor-42"),
//	    rpcclient.WithLabels(map[string]string{
//	        "fleet": "hvac",
//	        "zone":  "building-a",
//	    }),
//	)
func WithLabels(labels map[string]string) DialOption {
	return func(o *dialOptions) { o.labels = labels }
}

// WithHeartbeatInterval sets the per-agent heartbeat send interval.
// If not provided, agentHeartbeatInterval is used (synchronized with server config).
func WithHeartbeatInterval(interval time.Duration) DialOption {
	return func(o *dialOptions) { o.heartbeatInterval = interval }
}

// KeepaliveParams is an alias for grpc's keepalive.ClientParameters. It lets
// callers declare keepalive-typed values (e.g. function return types) without
// importing google.golang.org/grpc/keepalive directly; being a type alias
// (not a defined type), it is fully interchangeable with keepalive.ClientParameters.
type KeepaliveParams = keepalive.ClientParameters

// DefaultKeepaliveParams returns the recommended gRPC keepalive parameters for
// all A2A connections (workers, orchestrators, cluster dials). The 60-second
// ping interval keeps connections alive through typical NAT idle timeouts while
// staying clear of the relay's 30-second enforcement MinTime (nfltr's
// deploy/relay-settings.yaml: grpc.keepalive.enforcement_policy.min_time). The
// 20-second ACK timeout tolerates transient network delays without
// false-positive disconnections.
func DefaultKeepaliveParams() keepalive.ClientParameters {
	return keepalive.ClientParameters{
		Time:                60 * time.Second,
		Timeout:             20 * time.Second,
		PermitWithoutStream: true,
	}
}

// WithLiveness sets how the agent notices a relay gone without a FIN: the
// heartbeat interval it asks of the relay and how long past the relay's
// stated interval it waits for a frame (agentwire.Liveness.DeadAfter).
// Default agentwire.LivenessDefault. A relay that states no interval leaves
// liveness to the gRPC keepalive.
func WithLiveness(l agentwire.Liveness) DialOption {
	return func(o *dialOptions) { o.liveness = l }
}

// WithKeepalive enables gRPC transport-level keepalive on the underlying
// connection. This is recommended for nfltr worker connections to prevent
// TCP idle timeout when the worker is idle between task assignments.
func WithKeepalive(params keepalive.ClientParameters) DialOption {
	return func(o *dialOptions) { o.keepalive = &params }
}

// WithCapabilities advertises the agent's capabilities to the server.
// Capabilities describe what the agent can serve (e.g. "p2p", "ssh",
// "http", "a2a"). They are sent as the "x-agent-capabilities" gRPC header
// and displayed in peer listings.
func WithCapabilities(caps ...string) DialOption {
	return func(o *dialOptions) { o.capabilities = caps }
}

// CallOption configures a single outgoing call.
type CallOption func(*callOptions)

type callOptions struct {
	messageType string
}

type outboundFrame struct {
	frame  *pb.TunnelFrame
	result chan error
}

// WithMessageType overrides the message type (default "a2a-request").
func WithMessageType(mt string) CallOption {
	return func(o *callOptions) { o.messageType = mt }
}
