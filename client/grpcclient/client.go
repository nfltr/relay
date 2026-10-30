// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package grpcclient provides lightweight gRPC client connection helpers.
//
// This package has no dependency on server-side code (key stores, OPA,
// Prometheus, etc.) so it can be used by the tunnel-agent without pulling
// in heavy transitive dependencies like SQLite.
package grpcclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
	"weak"

	"github.com/nfltr/relay/client/relaytrust"
	"github.com/nfltr/relay/proto/wire/grpccodec"
	"github.com/nfltr/relay/proto/wire/tlsbatch"
	"google.golang.org/grpc"
	grpcbackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/experimental"
	"google.golang.org/grpc/keepalive"
)

// ClientConn is an alias for grpc.ClientConn. It lets callers hold a
// connection value returned by NewClientConn/NewMTLSClientConn without
// importing google.golang.org/grpc directly; being a type alias (not a
// defined type), it is fully interchangeable with grpc.ClientConn.
type ClientConn = grpc.ClientConn

// Option configures a client connection.
type Option func(*options)

type options struct {
	userAgent          string
	keepalive          *keepalive.ClientParameters
	insecureSkipVerify bool
}

// WithKeepalive enables gRPC keepalive with the given parameters.
func WithKeepalive(params keepalive.ClientParameters) Option {
	return func(o *options) { o.keepalive = &params }
}

// KeepaliveParams returns the gRPC keepalive parameters for a client
// connection to a relay (agents, a2a dials). Pings every 30 s keep the
// connection alive through relay flaps up to ~10 minutes; a 10 s ACK timeout
// aborts after 2 successive missed pings before the client reconnects. 30 s is
// the relay's enforcement MinTime (grpc.keepalive.enforcement_policy.min_time):
// a client pings Time after its last read (the previous ping's ack), so its
// pings reach the relay at least that far apart; never set Time below it.
func KeepaliveParams() keepalive.ClientParameters {
	return keepalive.ClientParameters{
		Time:                30 * time.Second,
		Timeout:             10 * time.Second,
		PermitWithoutStream: true,
	}
}

// NewClientConn creates a gRPC client connection using grpc.NewClient (lazy connect).
// The connection is established lazily on the first RPC call, so this function
// returns immediately without blocking.
// relayReconnectParams is how a connection redials a relay that went away. A
// restart or deploy is back within seconds, so the channel redials on the
// schedule tunnels use (cliutil's fast reconnect: 250 ms up to 1 s) instead of
// gRPC's default 1 s growing to 120 s, during which every call fails without
// dialing (G-R3: `wg socks5` keeps one connection and came back 17-22 s after
// a restart). The cost: while a relay stays down, a failed channel dials it
// about once a second (a refused TCP connect), like a tunnel in its fast window.
var relayReconnectParams = grpc.ConnectParams{
	Backoff: grpcbackoff.Config{
		BaseDelay:  250 * time.Millisecond,
		Multiplier: 1.6,
		Jitter:     0.2,
		MaxDelay:   time.Second,
	},
	MinConnectTimeout: 10 * time.Second,
}

func NewClientConn(secureConn bool, serverAddress string, serverPort int, opts ...Option) (*grpc.ClientConn, error) {
	var cfg options
	for _, o := range opts {
		o(&cfg)
	}

	w := &dialWatch{}
	dialOpts := append(buildDialOpts(&cfg), relayDialer(serverAddress, serverPort, w)...)

	if secureConn {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(
			ExplainTLS(tlsbatch.ClientCredentials(credentials.NewTLS(relayTLSConfig(&cfg)))),
		))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	target := fmt.Sprintf("%s:%d", serverAddress, serverPort)
	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating client for target: %s: %w", target, err)
	}
	watchDials(conn, w)
	return conn, nil
}

// relayTLSConfig is the TLS configuration of a secure connection to the
// relay without a client certificate.
func relayTLSConfig(cfg *options) *tls.Config {
	tlsCfg := &tls.Config{NextProtos: []string{"h2"}}
	if cfg.insecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	// A private relay's pinned certificate (relaytrust.PinEnv).
	return relaytrust.WithPin(tlsCfg, os.Getenv(relaytrust.PinEnv))
}

// ExplainTLS returns creds whose handshake errors say what to do when the
// relay's certificate is refused (relaytrust.Explain): gRPC reports them only
// as text. For credentials that honour the relay pin.
func ExplainTLS(creds credentials.TransportCredentials) credentials.TransportCredentials {
	return explainCreds{TransportCredentials: creds}
}

type explainCreds struct {
	credentials.TransportCredentials
}

func (c explainCreds) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	tc, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, conn)
	return tc, info, relaytrust.Explain(err)
}

func (c explainCreds) Clone() credentials.TransportCredentials {
	return explainCreds{TransportCredentials: c.TransportCredentials.Clone()}
}

// NewMTLSClientConn creates a gRPC client connection with mutual TLS.
// The client presents its certificate and validates the server against
// the given TLS config.
func NewMTLSClientConn(serverAddress string, serverPort int, tlsCfg *tls.Config, opts ...Option) (*grpc.ClientConn, error) {
	var cfg options
	for _, o := range opts {
		o(&cfg)
	}

	w := &dialWatch{}
	dialOpts := append(buildDialOpts(&cfg), relayDialer(serverAddress, serverPort, w)...)
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(tlsbatch.ClientCredentials(credentials.NewTLS(tlsCfg))))

	target := fmt.Sprintf("%s:%d", serverAddress, serverPort)
	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating mTLS client for target: %s: %w", target, err)
	}
	watchDials(conn, w)
	return conn, nil
}

// grpcWriteBatch is how much the transport collects before it writes
// (grpc-go's default is 32 KiB). Over TLS one batch is one write syscall
// (tlsbatch), so a larger batch costs fewer syscalls per byte; grpc-go
// pools the buffer and releases it when the connection goes idle. Small
// messages still go out at once: the transport writes when it runs out of
// work, not only when the batch is full.
const grpcWriteBatch = 256 << 10

func buildDialOpts(cfg *options) []grpc.DialOption {
	var opts []grpc.DialOption
	ua := cfg.userAgent
	if ua == "" {
		ua = os.Getenv("POD_ID")
	}
	if ua != "" {
		opts = append(opts, grpc.WithUserAgent(ua))
	}
	if cfg.keepalive != nil {
		opts = append(opts, grpc.WithKeepaliveParams(*cfg.keepalive))
	}
	opts = append(opts, ClientIdentity()...)
	opts = append(opts, grpc.WithConnectParams(relayReconnectParams))
	// HTTP/2 receive windows: what the relay may send this client
	// unacknowledged, so one stream moves at most window/RTT (relay ->
	// agent: uploads, request bodies). Static windows turn off grpc-go's
	// BDP estimator, which measured no better than 4 MiB static at 40 ms
	// RTT; 16 MiB static measured 3.5x (relay package
	// BenchmarkTCPTunnelThroughputRTT). The buffering it allows is the
	// client's own memory.
	opts = append(opts,
		grpc.WithInitialWindowSize(16<<20),
		grpc.WithInitialConnWindowSize(64<<20),
		experimental.WithBufferPool(grpccodec.Pool),
		grpc.WithWriteBufferSize(grpcWriteBatch),
		// The relay sends messages up to grpc.max_message_size (8 MiB: a
		// request body chunk). grpc-go's client default of 4 MiB made any
		// upload over ~4 MiB break the agent's stream.
		// Large messages skip grpc-go's buffer pool and response chunks
		// are sent without copying their payload (grpccodec).
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxRecvMessageSize),
			grpc.ForceCodecV2(grpccodec.NewLargeMessage()),
		),
	)
	return opts
}

// maxRecvMessageSize is the largest message the relay sends (its
// grpc.max_message_size default, 8 MiB).
const maxRecvMessageSize = 8 << 20

// RedialNow makes conn dial its relay now rather than when the channel's own
// backoff (relayReconnectParams, up to 1 s) ends, for callers that pace their
// redials themselves (relayoutage.RedialDelay): call it before the attempt.
// Without it an attempt made during that backoff fails at once with the last
// dial's error, so a client lagged a relay that was back by up to a second.
//
// It returns once the channel is READY, or once a dial made after the call
// failed (the relay is still down: the attempt fails with that dial's
// error, and the caller paces the next), never on a time alone: a channel in
// TRANSIENT_FAILURE stays there until a new dial is READY (pick_first's
// sticky failure, gRPC A62), so an attempt before that fails with the last
// dial's error, and a fixed wait lost the race to a slow handshake on a
// loaded machine. A backoff reset reaches only a backoff in progress, not a
// dial in flight at the call (started before the relay was back, it fails
// into a fresh backoff of up to 1.2 s): the reset is repeated every
// redialRecheck until a dial starts after the call.
// Guards: TestRedialNowOutlivesADialInFlight, TestRedialNowReachesARelayThatIsBack.
func RedialNow(ctx context.Context, conn *ClientConn) {
	w := watchOf(conn)
	bound := redialSettle
	if w == nil {
		bound = redialSettleBlind
	}
	ctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	since := w.snapshot()
	for {
		st := conn.GetState()
		if st != connectivity.TransientFailure && st != connectivity.Connecting {
			return // READY; IDLE or SHUTDOWN: the attempt dials, or fails, itself
		}
		now := w.snapshot()
		if now.failedSince(since) {
			return // the relay is still down, or does not serve
		}
		if now.started == since.started {
			conn.ResetConnectBackoff()
		}
		step, stop := context.WithTimeout(ctx, redialRecheck)
		conn.WaitForStateChange(step, st)
		stop()
		if ctx.Err() != nil {
			return
		}
	}
}

// redialRecheck is the channel's own first backoff: how soon a reset that
// raced a dial in flight is repeated.
var redialRecheck = relayReconnectParams.Backoff.BaseDelay

// redialSettle bounds RedialNow against a channel whose dial neither
// succeeds nor fails: a dial and its handshake end within the connect
// timeout (a silent path), after a dial in flight at the call did.
var redialSettle = 2 * relayReconnectParams.MinConnectTimeout

// redialSettleBlind bounds RedialNow on a channel whose dials it cannot see
// (an HTTPS proxy's): a relay still down costs the wait.
const redialSettleBlind = time.Second

// dialWatch counts a channel's dials (relayDial): those started and ended,
// and the last that connected.
type dialWatch struct {
	mu                    sync.Mutex
	started, ended, okSeq uint64
}

type dialCounts struct{ started, ended, okSeq uint64 }

func (w *dialWatch) dial(ctx context.Context, addr string) (net.Conn, error) {
	w.mu.Lock()
	w.started++
	seq := w.started
	w.mu.Unlock()
	c, err := relayDial(ctx, addr)
	w.mu.Lock()
	w.ended++
	if err == nil && seq > w.okSeq {
		w.okSeq = seq
	}
	w.mu.Unlock()
	return c, err
}

// failedSince reports whether a dial started after since failed: every
// one of them ended without connecting, or one connected and the channel
// dialled again after it (its handshake failed).
// ponytail: with several addresses (localhost: ::1 and 127.0.0.1) a dial
// of one may end this while another's is still to come; the caller's next
// attempt reaches it.
func (c dialCounts) failedSince(since dialCounts) bool {
	if c.started == since.started {
		return false
	}
	if c.okSeq <= since.started {
		return c.ended == c.started
	}
	return c.started > c.okSeq
}

// snapshot is w's counts; zero for nil.
func (w *dialWatch) snapshot() dialCounts {
	if w == nil {
		return dialCounts{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return dialCounts{w.started, w.ended, w.okSeq}
}

// dialWatches maps a channel to its dialWatch (ClientConn is grpc's own
// type): weakly, so a channel dropped by its owner is collected and its
// entry removed.
var dialWatches sync.Map // weak.Pointer[grpc.ClientConn] -> *dialWatch

func watchDials(conn *grpc.ClientConn, w *dialWatch) {
	k := weak.Make(conn)
	dialWatches.Store(k, w)
	runtime.AddCleanup(conn, func(k weak.Pointer[grpc.ClientConn]) { dialWatches.Delete(k) }, k)
}

func watchOf(conn *grpc.ClientConn) *dialWatch {
	w, _ := dialWatches.Load(weak.Make(conn))
	d, _ := w.(*dialWatch)
	return d
}
