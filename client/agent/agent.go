// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package agent provides an embeddable SDK for connecting a local HTTP service
// to a relay tunnel without requiring a separate binary.
//
// # API composition
//
// The package wraps the same primitives the nfltr CLI uses:
//   - [grpcclient.NewClientConn] / [grpcclient.NewMTLSClientConn] for gRPC transport
//     with keepalive and enlarged HTTP/2 flow-control windows (4 MB/stream, 16 MB/conn)
//   - [pb.NewDispatcherClient] + [pb.Dispatcher_ConnectHTTP] for the tunnel stream
//   - Route parsing is lifted into the
//     [Route] type so application code no longer needs string formatting.
//
// # Basic usage
//
//	a := agent.New(agent.Config{
//	    ServerAddr: "rpc.example.com:443",
//	    AgentID:      "my-service-01",
//	    APIKey:     os.Getenv("NFLTR_API_KEY"),
//	    TLS:        true,
//	    Routes: []agent.Route{
//	        {Backend: "http://localhost:8080"}, // default
//	    },
//	})
//
//	if err := a.Connect(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	log.Println("tunneling via", a.AgentID())
//	<-a.Done()
package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc/metadata"
)

// Route describes a single backend that the agent forwards traffic to.
// Exactly one of Backend must be set.
//
//   - Route{Backend: "http://localhost:8080"} — default/fallback route
//   - Route{Prefix: "api", Backend: "http://localhost:3001"} — prefix route:
//     requests to /api/... are forwarded to :3001 with the prefix stripped.
type Route struct {
	// Prefix is the first URL path segment used to select this route.
	// The empty string makes this the default (fallback) route.
	Prefix string

	// Backend is the HTTP URL of the local service (e.g. "http://localhost:8080").
	Backend string
}

// Config holds all parameters needed to connect to the relay.
// All fields have safe zero values; only AgentID and one of (APIKey / TLSConfig)
// are required for a minimal deployment.
type Config struct {
	// ServerAddr is the host:port of the relay's gRPC endpoint.
	// Default: "relay:9090"
	ServerAddr string

	// AgentID is the stable agent identity used for routing.
	// Required. Must be unique across all connected agents.
	AgentID string

	// Routes are the local HTTP backends this agent tunnels traffic to.
	// A request whose first path segment names no route goes to the
	// route with an empty Prefix (the default route); without one it is
	// answered 404. An empty, non-nil Routes serves no HTTP.
	// Default (nil): [{Backend: "http://localhost:8080"}]
	Routes []Route

	// APIKey is the plaintext API key sent in gRPC metadata (x-api-key).
	// Use one of APIKey or TLSConfig (mTLS); both may be set simultaneously.
	APIKey string

	// APIKeyFile, when set, names a file holding the credential, read again
	// at every connection attempt and used instead of APIKey: a short-lived
	// token another process rewrites before it expires (an OIDC token from
	// the organization's IdP) is taken on the next reconnect after the relay
	// ended the connection at the old token's expiry. The agent never
	// refreshes a token itself.
	APIKeyFile string

	// TLS enables one-way TLS for the gRPC connection when set to true.
	// Ignored when TLSConfig is provided.
	TLS bool

	// TLSConfig is used for mutual TLS. When set it overrides the TLS flag.
	TLSConfig *tls.Config

	// Retries is the number of connection attempts before giving up.
	// Default: 12
	Retries int

	// RetryWait is the longest wait between connection attempts (before
	// jitter): it caps relayoutage.RedialDelay after an outage's first
	// minute; redials within that minute wait a second at most.
	// Default: 5s
	RetryWait int // seconds

	// Drain is how long a stop (Connect's ctx ends, or Close) lets the TCP
	// sessions open through the agent run: the agent leaves the relay at
	// once (no new session reaches it) and closes its connection once its
	// sessions ended or Drain passed. 0: the sessions end with the stop.
	Drain time.Duration

	// RequestTimeout is the per-request timeout for forwarding to the local Backend.
	// Default: 60s
	RequestTimeout int // seconds

	// SkipVerify disables TLS verification for the local Backend during HTTP
	// forwarding. This is a developer-only option; never use in production.
	SkipVerify bool

	// RewriteHost sends a backend its own host (the Backend URL's) as the
	// request's Host, as nginx's proxy_pass does. By default the backend gets
	// the public host the visitor asked for, as Caddy, ngrok and cloudflared
	// send it; X-Forwarded-Host carries it either way. For backends that
	// accept only their own host name (dev servers' host checks, name-based
	// virtual hosts). E2EE sessions served by an E2EESetup take
	// E2EESetup.RewriteHost instead.
	RewriteHost bool

	// TCPTunnel enables raw TCP tunneling via the ConnectTCP gRPC stream.
	// When true the agent opens a second bidirectional stream alongside
	// ConnectHTTP that allows the server to proxy SSH, RDP, database, and
	// other TCP traffic through to local targets.
	// Default: false
	TCPTunnel bool

	// TCPForwardAddr overrides the server-provided target address for TCP
	// tunnel sessions. When set, all incoming TCP connections are forwarded
	// to this address instead of the default localhost:<port>.
	// Format: "host:port" (e.g. "kubernetes.default.svc:443").
	TCPForwardAddr string

	// Capabilities is a list of capability identifiers advertised to the
	// server via the x-agent-capabilities metadata header (e.g. "terminal").
	// The server uses these to enable UI features like the dashboard Term button.
	Capabilities []string

	// Concurrency is the maximum number of HTTP requests dispatched to
	// goroutines simultaneously.  Increasing this value improves throughput
	// under bursty load at the cost of higher memory usage.
	// Default: 20
	Concurrency int

	// Liveness is how the agent notices a relay gone without a FIN: the
	// heartbeat interval it asks of the relay, and how long past the interval
	// the relay states it waits for a frame (agentwire.Liveness.DeadAfter).
	// Default (zero): agentwire.LivenessDefault. A relay that states no
	// interval leaves HeartbeatRecvThreshold's 45s.
	Liveness agentwire.Liveness

	// Transport is the agent link's transport toward a relay that takes it
	// (TransportTCP, TransportQUIC, TransportAuto; "" is TransportTCP):
	// the TCP tunnel's sessions ride it, the gRPC streams the fallback.
	Transport string

	// HeartbeatRecvThreshold, when set, is the maximum time the agent waits
	// without any message from the server before treating the stream as dead,
	// whatever Liveness and the relay say. Any received message, heartbeat or
	// data, resets it. Negative turns it off.
	HeartbeatRecvThreshold time.Duration

	// Logger is the structured logger used for agent events.
	// When nil, the default slog logger is used.
	Logger *slog.Logger
}

// Option is a functional modifier applied after Config is parsed.
type Option func(*agent)

// WithLabels sets additional key=value label pairs sent in gRPC metadata.
// Labels are used by the server for fleet token matching.
func WithLabels(labels map[string]string) Option {
	return func(a *agent) {
		a.labels = labels
	}
}

// WithTLSCert configures the agent to terminate E2EE TLS connections using
// the provided certificate and key files.  The certificate is presented to
// clients connecting through the server's SNI router.
func WithTLSCert(certFile, keyFile string) Option {
	return func(a *agent) {
		cert, fp, err := loadCertFromFiles(certFile, keyFile)
		if err != nil {
			panic("agent.WithTLSCert: " + err.Error())
		}
		a.e2eeTLS = newE2EETLSConfig(cert, a.cfg.AgentID)
		a.e2eeTLS.rewriteHost = a.cfg.RewriteHost
		a.logger.Info("e2ee: loaded TLS certificate",
			"fingerprint", fp, "cert", certFile)
	}
}

// WithSelfSignedTLS configures the agent to auto-generate an ECDSA P-256
// self-signed certificate for E2EE TLS termination.  The SHA-256 fingerprint
// is logged so the client can pin it for trust-on-first-use verification.
func WithSelfSignedTLS() Option {
	return func(a *agent) {
		cert, fp, err := generateSelfSignedCert(a.cfg.AgentID)
		if err != nil {
			panic("agent.WithSelfSignedTLS: " + err.Error())
		}
		a.e2eeTLS = newE2EETLSConfig(cert, a.cfg.AgentID)
		a.e2eeTLS.rewriteHost = a.cfg.RewriteHost
		a.logger.Info("e2ee: generated self-signed TLS certificate",
			"fingerprint", fp, "agent_id", a.cfg.AgentID)
	}
}

// WithBackendTransport wraps the transport that carries the agent's HTTP
// tunnel requests to its backends, on the ConnectHTTP stream and on link
// sessions alike: a wrapper sees each request the agent sends a backend
// (RequestOf its context says what the relay asked) and the response, and
// may answer itself (a response it returns without calling next never
// reaches the backend).
func WithBackendTransport(wrap func(next http.RoundTripper) http.RoundTripper) Option {
	return func(a *agent) { a.wrapTransport = wrap }
}

// WithMetadata adds key/value pairs to every connection's ConnectHTTP
// metadata; the agent's own keys (identity, routes, labels, E2EE
// fingerprint, ...) override them.
func WithMetadata(pairs ...string) Option {
	return func(a *agent) { a.metadata = append(a.metadata, pairs...) }
}

// Connection is a connection to the relay that the relay accepted, as
// WithConnected sees it.
type Connection struct {
	AgentID string      // the identity the relay resolved
	Header  metadata.MD // the relay's accept header (x-admin-message, ...)
	First   bool        // the agent's first connection
	// HTTP is the agent's HTTP tunnel handler, for a Tunnel that serves
	// it on link sessions.
	HTTP http.Handler
	// Done is closed once the connection has ended (the agent left it,
	// moved off it, or the relay ended it).
	Done <-chan struct{}
}

// WithConnected calls fn with each connection the relay accepts, before
// the agent serves it. fn returns the Tunnel the connection's TCP streams
// serve, as given (nil: the agent's own, from Config), or an error that
// stops the agent: Connect returns it for the first connection, Err after.
// A returned Tunnel's E2EE becomes the agent's: later connections announce
// its fingerprint.
func WithConnected(fn func(Connection) (*Tunnel, error)) Option {
	return func(a *agent) { a.connected = fn }
}

// Agent is the public interface for an embedded relay tunnel agent.
type Agent interface {
	// Connect dials the relay and starts the tunnel stream in the
	// background. It blocks until the first successful connection is
	// established (or all retries are exhausted), then returns.
	// Once connected, the agent runs until ctx is cancelled or Close is called.
	// A failed Connect closes Done. Call it once per agent.
	Connect(ctx context.Context) error

	// AgentID returns the agent identity string used for routing.
	AgentID() string

	// Done returns a channel that is closed when the agent stops running.
	Done() <-chan struct{}

	// Connected reports whether the agent holds a connection the relay
	// accepted: through a make-before-break move it stays true (the new
	// connection is accepted before the old one ends). A flag set per
	// WithConnected call and cleared by that connection's Done is not
	// this: the old connection of a move ends last.
	Connected() bool

	// Err is why the agent stopped once Done is closed: nil when its
	// context ended or Close was called, else the error that ended it
	// (non-retryable, or WithConnected's).
	Err() error

	// Close signals the agent to stop and waits for the tunnel stream
	// to drain. It is safe to call multiple times.
	Close()

	// RotateE2EECert generates a new self-signed E2EE TLS certificate and
	// notifies the server of the new fingerprint via a control frame on the
	// active ConnectTCP stream.  Returns the new SHA-256 fingerprint.
	// Returns an error if E2EE is not configured.
	RotateE2EECert() (string, error)

	// RotateE2EECertFromFiles loads a new E2EE TLS certificate from PEM
	// files and notifies the server.  Returns the new fingerprint.
	RotateE2EECertFromFiles(certFile, keyFile string) (string, error)

	// Stats returns the agent's counters (Stats): read when called, for
	// a metrics collector at scrape time.
	Stats() Stats
}

// New creates a new Agent from the given Config and options.
// The agent is not connected until Connect is called.
func New(cfg Config, opts ...Option) Agent {
	applyDefaults(&cfg)

	routes, err := parseRoutes(cfg.Routes)
	if err != nil {
		panic("agent.New: invalid routes: " + err.Error())
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	a := &agent{
		cfg:          cfg,
		routes:       routes,
		logger:       logger.With("agent_id", cfg.AgentID),
		moveRetryFor: moveRetryFor,
		done:         make(chan struct{}),
		stats:        &stats{},
	}
	for _, opt := range opts {
		opt(a)
	}
	a.client = newBackendClient(cfg)
	if a.wrapTransport != nil {
		a.client.Transport = a.wrapTransport(a.client.Transport)
	}
	a.httpHandler = newTunnelHandler(cfg.AgentID, routes, a.client, cfg.RewriteHost, a.logger)
	return a
}

// applyDefaults fills zero-value fields in cfg with safe defaults.
func applyDefaults(cfg *Config) {
	if cfg.ServerAddr == "" {
		cfg.ServerAddr = "relay:9090"
	}
	if cfg.Routes == nil {
		cfg.Routes = []Route{{Backend: "http://localhost:8080"}}
	}
	if cfg.Retries == 0 {
		cfg.Retries = 12
	}
	if cfg.RetryWait == 0 {
		cfg.RetryWait = 5
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 60
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 20
	}
	if cfg.Liveness == (agentwire.Liveness{}) {
		cfg.Liveness = agentwire.LivenessDefault
	}
}

// ---------------------------------------------------------------------------
// internal struct
// ---------------------------------------------------------------------------

type agent struct {
	cfg    Config
	park   *linkPark // the agent link between primaries (RelayDialer.park)
	routes routeTable
	logger *slog.Logger

	moveRetryFor time.Duration // a move's new connection, all attempts (move.go)

	// client forwards HTTP tunnel requests to the backends (both ways
	// they come); httpHandler serves the HTTP tunnel on link sessions.
	client        *http.Client
	httpHandler   *TunnelHandler
	wrapTransport func(http.RoundTripper) http.RoundTripper // WithBackendTransport

	metadata  []string                          // WithMetadata
	connected func(Connection) (*Tunnel, error) // WithConnected
	live      atomic.Int32                      // accepted connections not yet ended (Connected)
	stats     *stats                            // Stats

	errMu sync.Mutex
	err   error // why the agent stopped (Err)

	// fleet / pool labels (WithLabels option)
	labels map[string]string

	// E2EE TLS termination (WithTLSCert / WithSelfSignedTLS option)
	e2eeTLS *e2eeTLSConfig

	// WireGuard exit (WithWireGuardExit; package wgexit's options)
	wgExit WireGuardExit
	wgx    WireGuardTunnel // the running tunnel

	// initErr captures errors from functional options so Connect() can surface them.
	initErr error

	// lifecycle
	cancel context.CancelFunc
	done   chan struct{}
}

func (a *agent) AgentID() string       { return a.cfg.AgentID }
func (a *agent) Done() <-chan struct{} { return a.done }
func (a *agent) Connected() bool       { return a.live.Load() > 0 }
func (a *agent) Stats() Stats          { return a.stats.snapshot(int64(a.live.Load())) }

func (a *agent) Err() error {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	return a.err
}

func (a *agent) stopWith(err error) {
	a.errMu.Lock()
	a.err = err
	a.errMu.Unlock()
}

func (a *agent) Close() {
	a.closeWireGuard()
	if a.cancel != nil {
		a.cancel()
		<-a.done
	}
}

var errE2EENotConfigured = fmt.Errorf("e2ee tls is not configured")

func (a *agent) RotateE2EECert() (string, error) {
	if a.e2eeTLS == nil {
		return "", errE2EENotConfigured
	}
	return a.e2eeTLS.rotateCert()
}

func (a *agent) RotateE2EECertFromFiles(certFile, keyFile string) (string, error) {
	if a.e2eeTLS == nil {
		return "", errE2EENotConfigured
	}
	return a.e2eeTLS.rotateCertFromFiles(certFile, keyFile)
}

// serverHost and serverPort split cfg.ServerAddr into components
// accepted by grpcclient.NewClientConn.
func (a *agent) serverHostPort() (string, int, error) {
	return splitHostPort(a.cfg.ServerAddr)
}
