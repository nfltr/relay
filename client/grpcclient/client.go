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
	"time"

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

	dialOpts := append(buildDialOpts(&cfg), relayDialer(serverAddress, serverPort)...)

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

	dialOpts := append(buildDialOpts(&cfg), relayDialer(serverAddress, serverPort)...)
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(tlsbatch.ClientCredentials(credentials.NewTLS(tlsCfg))))

	target := fmt.Sprintf("%s:%d", serverAddress, serverPort)
	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating mTLS client for target: %s: %w", target, err)
	}
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
// The reset takes effect asynchronously; this waits, at most redialSettle,
// for the channel to leave TRANSIENT_FAILURE so the attempt sees the new dial.
func RedialNow(ctx context.Context, conn *ClientConn) {
	conn.ResetConnectBackoff()
	ctx, cancel := context.WithTimeout(ctx, redialSettle)
	defer cancel()
	conn.WaitForStateChange(ctx, connectivity.TransientFailure)
}

const redialSettle = 100 * time.Millisecond
