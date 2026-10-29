// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/nfltr/relay/client/grpcclient"
	"github.com/nfltr/relay/client/relayoutage"
	"github.com/nfltr/relay/client/rpcclient"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"github.com/nfltr/relay/proto/wire/chunking"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Connect dials the relay, establishes the ConnectHTTP tunnel stream with
// retry logic, fires the optional share-URL callback, and launches the message-
// processing loop in a background goroutine.
//
// It blocks until the first successful connection or all retry attempts are
// exhausted. The context must remain live for the agent to keep running;
// cancelling it shuts the agent down cleanly.
//
// If the stream drops with any error (e.g. server restart), the agent
// automatically reconnects with backoff. Done() is only closed when the
// context is cancelled or a fatal error (rpcclient.FatalClass) occurs.
func (a *agent) Connect(ctx context.Context) error {
	if a.initErr != nil {
		return a.initErr
	}

	// Create the cancellable run context before dialing so that the initial
	// stream's gRPC context is derived from runCtx. This ensures that
	// a.Close() → a.cancel() cancels the stream and unblocks stream.Recv().
	runCtx, cancel := context.WithCancel(ctx)
	a.park = newLinkPark(runCtx)
	a.cancel = cancel

	// Establish the first connection synchronously so the caller gets an
	// immediate error if the server is unreachable.
	// A failed Connect stops the agent: Done closes, so Close returns.
	conn, client, stream, streamCtx, err := a.connectOnce(runCtx, time.Now(), a.cfg.Retries)
	if err != nil {
		cancel()
		close(a.done)
		return err
	}
	acc, err := a.accept(stream, true)
	if err != nil {
		_ = conn.Close()
		cancel()
		close(a.done)
		return err
	}

	// Run the message-processing loop with automatic reconnection.
	go a.runWithReconnect(runCtx, cancel, conn, client, stream, streamCtx, acc)

	return nil
}

// accepted is a connection's part WithConnected decided: the tunnel its
// TCP streams serve (nil: the agent's own) and its Done channel.
type accepted struct {
	tunnel *Tunnel
	done   chan struct{}
}

// accept hands a connection the relay accepted to WithConnected.
func (a *agent) accept(stream pb.Dispatcher_ConnectHTTPClient, first bool) (accepted, error) {
	acc := accepted{done: make(chan struct{})}
	if a.connected == nil {
		return acc, nil
	}
	header, _ := stream.Header()
	t, err := a.connected(Connection{AgentID: a.cfg.AgentID, Header: header, First: first, HTTP: a.httpHandler, Done: acc.done})
	if err != nil {
		return acc, err
	}
	if t != nil && t.E2EE != nil {
		a.e2eeTLS = t.E2EE.cfg // later connections announce its fingerprint
	}
	acc.tunnel = t
	return acc, nil
}

// maxReconnectBackoff is the ceiling for exponential backoff between reconnect
// attempts.
const maxReconnectBackoff = 60 * time.Second

// stableConnectionAfter is how long a connection must stay up for its drop
// to restart the redial schedule; a relay that accepts and drops at once
// (e.g. another session holding the agent ID) keeps backing off.
const stableConnectionAfter = 5 * time.Second

// gracefulReconnectDelay is the fast-path reconnect delay used when the server
// closes the stream via a graceful stop (GOAWAY / EOF). Rolling restarts and
// scheduled maintenance always produce this pattern, so reconnecting quickly
// reduces visible latency for end users.
const gracefulReconnectDelay = 50 * time.Millisecond

// isGracefulStopError returns true when the stream ended because the server
// issued a graceful shutdown (HTTP/2 GOAWAY with NO_ERROR, clean EOF, or a
// plain io.EOF from the gRPC stream) or cancelled the stream (e.g. server-side
// context cancel, cloud proxy idle-timeout). These are expected during rolling
// restarts and idle evictions; the agent should reconnect immediately rather
// than waiting out the full exponential backoff.
func isGracefulStopError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	if s, ok := status.FromError(err); ok && s.Code() == codes.Canceled {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "graceful_stop") ||
		strings.Contains(errStr, "error reading from server: eof") ||
		strings.Contains(errStr, "goaway") ||
		strings.Contains(errStr, "transport is closing") ||
		strings.Contains(errStr, "closing transport")
}

// superviseConnectionCycle runs the primary HTTP stream loop and an optional
// auxiliary TCP/E2EE loop as one connection lifecycle. If either loop exits,
// the shared gRPC connection is closed so reconnect logic can take over.
func superviseConnectionCycle(ctx context.Context, conn io.Closer, primary func() error, auxiliary func() error) error {
	primaryErrCh := make(chan error, 1)
	go func() {
		primaryErrCh <- primary()
	}()

	if auxiliary == nil {
		err := <-primaryErrCh
		_ = conn.Close()
		return err
	}

	auxiliaryErrCh := make(chan error, 1)
	go func() {
		if err := auxiliary(); err != nil && ctx.Err() == nil {
			auxiliaryErrCh <- err
		}
	}()

	select {
	case err := <-primaryErrCh:
		_ = conn.Close()
		return err
	case err := <-auxiliaryErrCh:
		_ = conn.Close()
		select {
		case primaryErr := <-primaryErrCh:
			if primaryErr == nil {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	case <-ctx.Done():
		_ = conn.Close()
		return ctx.Err()
	}
}

// tunnelTargets is what a connection's TCP streams serve: t as given, or
// (t nil) the agent's own tunnel from Config, its HTTP sessions always and
// raw and E2EE sessions with TCPTunnel. needed: the connection fails with
// its TCP tunnel (not only when it serves no more than HTTP sessions, which
// then come on the ConnectHTTP stream).
func (a *agent) tunnelTargets(t *Tunnel) (targets sessionTargets, e2ee *e2eeTLSConfig, needed bool) {
	if t != nil {
		if t.E2EE != nil {
			e2ee = t.E2EE.cfg
		}
		return sessionTargets{forwardAddr: t.ForwardAddr, defaultBackend: t.DefaultBackend, services: t.Services, http: t.HTTP, noRaw: !t.RawTCP && t.Services == nil},
			e2ee, t.RawTCP || t.E2EE != nil || t.Services != nil
	}
	targets = sessionTargets{http: a.httpHandler, noRaw: !a.cfg.TCPTunnel}
	if a.cfg.TCPTunnel {
		targets.forwardAddr, e2ee = a.cfg.TCPForwardAddr, a.e2eeTLS
		if def := a.routes.defaultRoute(); def != nil {
			targets.defaultBackend = def.backend.String()
		}
	}
	return targets, e2ee, a.cfg.TCPTunnel
}

// runWithReconnect runs processStream and reconnects on every error, with
// the bounded, jittered relayoutage.RedialDelay backoff. It closes a.done
// only when the context is cancelled or the error is on the closed fatal
// list (rpcclient.FatalClass: auth, version, config, session replaced); the
// error it stops with then carries a hint. A WithConnected hook's error
// also ends it: that is the caller's own decision.
func (a *agent) runWithReconnect(
	ctx context.Context,
	cancel context.CancelFunc,
	conn *grpc.ClientConn,
	client pb.DispatcherClient,
	stream pb.Dispatcher_ConnectHTTPClient,
	streamCtx context.Context,
	acc accepted,
) {
	defer close(a.done)
	defer cancel()

	// failures counts consecutive non-graceful drops of connections that did
	// not stay up for stableConnectionAfter; it sets the redial delay.
	failures := 0
	var outageSince time.Time // when the current outage began
	release := func() {}      // ends a move's stream context once its connection closed (moveConnect)

	for {
		startedAt := time.Now()
		var mv *move
		if a.canMove() {
			mv = newMove()
		}
		growth := &tcpStreamGrowth{} // shared by this cycle's streams
		if mv != nil {
			growth = mv.tcp
		}
		targets, e2ee, needed := a.tunnelTargets(acc.tunnel)
		tcpCtx, tcpStreamCtx, cycleCtx, endTCP := drainContexts(ctx, streamCtx, a.cfg.Drain)
		auxiliary := func() error {
			err := runTCPTunnel(tcpCtx, client, a.relayDialer(), tcpStreamCtx, targets, e2ee, a.logger, growth)
			switch {
			case err == nil:
				return nil
			case !needed:
				// HTTP sessions only: the HTTP tunnel goes on on ConnectHTTP.
				a.logger.Info("http on link sessions unavailable; requests come on the gRPC stream", "error", err)
				return nil
			}
			return fmt.Errorf("tcp tunnel: %w", err)
		}

		// Run the message-processing loop until either stream ends.
		cycle := make(chan error, 1)
		go func(conn io.Closer, stream pb.Dispatcher_ConnectHTTPClient, done chan struct{}, release func()) {
			defer close(done)
			defer release()
			defer endTCP()
			cycle <- superviseConnectionCycle(
				cycleCtx,
				conn,
				func() error {
					err := processStream(ctx, stream, a.cfg.AgentID, a.routes, a.cfg, a.client, a.logger, a.wgx, mv, growth.linkUp)
					switch {
					case waitsForTCPSessions(err):
						growth.waitIdle(ctx) // its TCP sessions end before the connection closes
					case mv != nil && ctx.Err() == nil && relayLetGo(err):
						// The relay let this connection go (a leaving
						// replica that could not move it, a graceful stop):
						// connect again now, as on MOVE_RECONNECT, and
						// close this one once the new one is up (or the
						// move gave up) and its TCP sessions ended.
						mv.askReconnect()
						select {
						case <-mv.connected:
						case <-time.After(a.moveRetryFor):
						case <-ctx.Done():
						}
						growth.waitIdle(ctx)
					case ctx.Err() != nil && a.cfg.Drain > 0:
						// Stopped: the ConnectHTTP stream ended (the relay
						// sends this agent nothing new); its TCP sessions
						// run until they end or Drain passes.
						wctx, cancel := context.WithTimeout(tcpCtx, a.cfg.Drain)
						growth.waitIdle(wctx)
						cancel()
					}
					return err
				},
				auxiliary,
			)
		}(conn, stream, acc.done, release)

		var streamErr error
		if mv == nil {
			streamErr = <-cycle
		} else {
			select {
			case streamErr = <-cycle:
			case <-mv.reconnect:
				// Make before break: the new connection first, then the
				// old one is told and closes once it has no request left.
				nconn, nclient, nstream, nstreamCtx, nrelease, err := a.moveConnect(ctx)
				var nacc accepted
				if err == nil {
					if nacc, err = a.accept(nstream, false); err != nil {
						_ = nconn.Close()
						nrelease()
						a.stopWith(err)
						return
					}
				}
				if err == nil {
					close(mv.connected)
					go func() {
						err := <-cycle
						a.logger.Info("moved to a new relay connection; the old one is closed", "old_end", err)
					}()
					conn, client, stream, streamCtx, acc, release = nconn, nclient, nstream, nstreamCtx, nacc, nrelease
					failures = 0
					a.logger.Info("reconnected before leaving the old relay connection", "server", a.cfg.ServerAddr)
					continue
				}
				if ctx.Err() != nil {
					return
				}
				a.logger.Warn("move: the new connection failed; staying until the relay lets this one go", "error", err)
				streamErr = <-cycle
			}
		}

		_ = conn.Close()

		// Context cancelled — clean shutdown.
		if ctx.Err() != nil {
			return
		}

		// Only a fatal class ends the agent; any other error redials.
		if rpcclient.FatalClass(streamErr) != rpcclient.NotFatal {
			err := rpcclient.FatalError(streamErr)
			a.logger.Error("tunnel stream ended with a fatal error", "error", err)
			a.stopWith(err)
			return
		}

		if time.Since(startedAt) >= stableConnectionAfter {
			failures = 0
		}
		if failures == 0 {
			outageSince = time.Now()
		}

		// Graceful stop (GOAWAY / clean EOF / nil — clean server-side stream
		// close): reconnect immediately without consuming backoff budget so
		// users see minimal disruption during planned maintenance windows.
		// Otherwise redial on the shared relay redial schedule: a relay that
		// restarts is back within about a second, so the first redials are
		// short, then they back off to maxReconnectBackoff.
		graceful := streamErr == nil || isGracefulStopError(streamErr)
		switch {
		case streamErr == nil:
			a.logger.Info("stream closed cleanly by server, reconnecting fast")
		case graceful:
			a.logger.Info("server graceful stop detected, reconnecting fast")
		}
		for {
			wait := gracefulReconnectDelay
			if !graceful {
				failures++
				wait = relayoutage.RedialDelay(failures, outageSince, maxReconnectBackoff)
				a.logger.Warn("connection lost, reconnecting", "error", streamErr, "backoff", wait.Truncate(time.Millisecond))
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}

			var reconnErr error
			conn, client, stream, streamCtx, reconnErr = a.connectOnce(ctx, outageSince, 0)
			release = func() {}
			if reconnErr == nil {
				var hookErr error
				if acc, hookErr = a.accept(stream, false); hookErr != nil {
					_ = conn.Close()
					a.stopWith(hookErr)
					return
				}
				break
			}
			if ctx.Err() != nil {
				return
			}
			if rpcclient.FatalClass(reconnErr) != rpcclient.NotFatal {
				err := rpcclient.FatalError(reconnErr)
				a.logger.Error("reconnect failed with a fatal error", "error", err)
				a.stopWith(err)
				return
			}
			// Redial; never run a cycle on the failed attempt's nil stream.
			graceful, streamErr = false, reconnErr
		}
		a.logger.Info("reconnected successfully", "server", a.cfg.ServerAddr)
	}
}

// waitRedial waits d before the next connect attempt on conn, or less when
// conn reaches the relay meanwhile (the channel keeps dialing on its own):
// the redial delay paces attempts a relay refuses, not finding a relay that
// is back. Guard: TestRedialWaitEndsWhenTheRelayIsBack.
func waitRedial(ctx context.Context, conn *grpc.ClientConn, d time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	if conn.GetState() == connectivity.Ready {
		<-ctx.Done()
		return
	}
	conn.Connect()
	for s := conn.GetState(); s != connectivity.Ready; s = conn.GetState() {
		if !conn.WaitForStateChange(ctx, s) {
			return
		}
	}
}

// dialRelay builds a gRPC connection to the relay with keepalive and
// enlarged HTTP/2 flow-control windows, so the agent can stream large
// responses (video, audio) without stalling on WINDOW_UPDATE round-trips.
func (a *agent) dialRelay(host string, port int) (*grpc.ClientConn, error) {
	kp := grpcclient.WithKeepalive(grpcclient.KeepaliveParams())
	var conn *grpc.ClientConn
	var err error
	if a.cfg.TLSConfig != nil {
		conn, err = grpcclient.NewMTLSClientConn(host, port, a.cfg.TLSConfig, kp)
	} else {
		conn, err = grpcclient.NewClientConn(a.cfg.TLS, host, port, kp)
	}
	if err != nil {
		return nil, fmt.Errorf("agent: gRPC dial %s:%d: %w", host, port, err)
	}
	return conn, nil
}

// relayDialer opens further connections to the relay (a busy TCP
// tunnel's auxiliary and data connections).
func (a *agent) relayDialer() RelayDialer {
	return RelayDialer{
		GRPC: func() (*grpc.ClientConn, error) {
			host, port, err := a.serverHostPort()
			if err != nil {
				return nil, err
			}
			return a.dialRelay(host, port)
		},
		Data: func(ctx context.Context) (net.Conn, error) {
			host, port, err := a.serverHostPort()
			if err != nil {
				return nil, err
			}
			return grpcclient.DialConn(ctx, a.cfg.TLS, a.cfg.TLSConfig, host, port)
		},
		Liveness:  a.cfg.Liveness,
		Transport: a.cfg.Transport,
		QUIC:      a.quicDialer(),
		park:      a.park,
	}
}

// quicDialer reaches the relay over QUIC; nil when the agent dials it in
// plaintext (QUIC is TLS only) or its address does not parse.
func (a *agent) quicDialer() *QUICDialer {
	host, _, err := a.serverHostPort()
	if err != nil {
		return nil
	}
	tc := grpcclient.RelayTLS(a.cfg.TLS, a.cfg.TLSConfig, host)
	if tc == nil {
		return nil
	}
	return &QUICDialer{Host: host, TLS: tc}
}

// connectOnce performs a single connection attempt: dials gRPC, attaches
// metadata, and opens the ConnectHTTP stream with retry, paced by the relay
// redial schedule for an outage that began at since.
func (a *agent) connectOnce(ctx context.Context, since time.Time, attempts int) (*grpc.ClientConn, pb.DispatcherClient, pb.Dispatcher_ConnectHTTPClient, context.Context, error) {
	host, port, err := a.serverHostPort()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	conn, err := a.dialRelay(host, port)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Attach outgoing metadata: API key + advertised route names + labels + capabilities.
	md := metadata.Pairs(a.metadata...)
	key, err := a.apiKey()
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, nil, err
	}
	if key != "" {
		md.Set("x-api-key", key)
	}
	if a.cfg.AgentID != "" {
		md.Set("x-agent-id", a.cfg.AgentID)
	}
	if names := a.routes.routeNames(); names != "" {
		md.Set("x-routes", names)
	}
	if len(a.cfg.Capabilities) > 0 {
		md.Set("x-agent-capabilities", strings.Join(a.cfg.Capabilities, ","))
	}
	if labels := agentwire.EncodeLabels(a.labels); labels != "" {
		md.Set(agentwire.LabelsKey, labels)
	}
	// Advertise E2EE TLS certificate fingerprint so the server can store
	// it in the endpoint registry and expose it via the TLS info API.
	if a.e2eeTLS != nil {
		md.Set("x-tls-fingerprint", a.e2eeTLS.Fingerprint())
	}
	// processStream reads cancel/ack frames and streams uploads.
	md.Set(chunking.FlowControlMetadataKey, chunking.FlowControlUploads)
	if a.canMove() {
		md.Set(agentwire.MoveKey, "1")
	}
	// The heartbeat this agent's liveness asks of the relay.
	if kv := agentwire.HeartbeatPairs(agentwire.HeartbeatAskKey, a.cfg.Liveness.Interval); kv != nil {
		md.Set(kv[0], kv[1])
	}
	// Send the WireGuard public key and end-to-end protocol.
	a.setWireGuardMetadata(md)
	streamCtx := metadata.NewOutgoingContext(ctx, md)

	client := pb.NewDispatcherClient(conn)

	// Retry loop — mirrors the nfltr CLI. attempts 0: until one connects
	// or fails for good.
	var stream pb.Dispatcher_ConnectHTTPClient
	for attempt := 1; attempts == 0 || attempt <= attempts; attempt++ {
		stream, err = client.ConnectHTTP(streamCtx)
		if err == nil {
			break
		}
		if !isRetryableError(err) {
			_ = conn.Close()
			return nil, nil, nil, nil, fmt.Errorf("agent: connect failed: %w", err)
		}
		if attempt == attempts {
			_ = conn.Close()
			return nil, nil, nil, nil, fmt.Errorf("agent: failed to connect after %d attempts: %w", attempts, err)
		}
		wait := relayoutage.RedialDelay(attempt, since, time.Duration(a.cfg.RetryWait)*time.Second)
		a.logger.Warn("connection attempt failed, retrying",
			"attempt", attempt, "max", attempts,
			"wait", wait.Truncate(time.Millisecond), "error", err)
		if waitRedial(ctx, conn, wait); ctx.Err() != nil {
			_ = conn.Close()
			return nil, nil, nil, nil, ctx.Err()
		}
		grpcclient.RedialNow(ctx, conn) // dial now, not when the channel's own backoff ends
	}

	a.logger.Info("tunnel connected", "server", a.cfg.ServerAddr, "tls", a.cfg.TLS || a.cfg.TLSConfig != nil)

	// Read the server-resolved agent identity. The server scopes --name
	// to the key's stored identity to prevent global name collisions.
	header, headerErr := stream.Header()
	if headerErr == nil && len(header.Get("x-resolved-agent-id")) == 0 {
		// A relay accepts a stream with the identity it resolved; one it
		// ended before accepting it (e.g. a declaration it refuses) says
		// why in its status.
		_, err := stream.Recv()
		_ = conn.Close()
		if err == nil || errors.Is(err, io.EOF) {
			err = errors.New("the relay ended the stream without accepting it")
		}
		return nil, nil, nil, nil, fmt.Errorf("agent: the relay refused the connection: %w", err)
	}
	if headerErr == nil {
		if vals := header.Get("x-resolved-agent-id"); len(vals) > 0 && vals[0] != "" {
			if vals[0] != a.cfg.AgentID {
				a.logger.Info("resolved agent identity", "requested", a.cfg.AgentID, "resolved", vals[0])
				a.cfg.AgentID = vals[0]
				a.httpHandler.setAgentID(vals[0])
			}
		}
		if vals := header.Get("x-admin-message"); len(vals) > 0 && vals[0] != "" {
			a.logger.Info("admin message", "message", vals[0])
		}
		// WireGuard: the assigned address; refuse a relay-terminated relay.
		if wgErr := a.startWireGuardFromHeader(ctx, header); wgErr != nil {
			_ = conn.Close()
			return nil, nil, nil, nil, wgErr
		}
	}

	return conn, client, stream, streamCtx, nil
}

// canMove: the agent moves off a leaving relay replica make-before-break
// (move.go). A WireGuard exit or client does not: its tunnel's packets go
// through one stream.
func (a *agent) canMove() bool { return !a.wireGuardEnabled() }

// isRetryableError returns true for transient transport/server failures where
// reconnecting is likely to succeed.
func isRetryableError(err error) bool {
	if errors.Is(err, errNoServerActivity) {
		return true
	}
	if s, ok := status.FromError(err); ok {
		switch s.Code() {
		case codes.Unavailable, codes.Internal, codes.Aborted,
			codes.ResourceExhausted, codes.Canceled,
			codes.AlreadyExists: // the agent ID's other session ends with it
			return true
		case codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument, codes.FailedPrecondition:
			return false
		}
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		return isRetryableError(unwrapped)
	}
	errStr := strings.ToLower(err.Error())
	switch {
	case strings.Contains(errStr, "operation timed out"),
		strings.Contains(errStr, "connection reset"),
		strings.Contains(errStr, "connection refused"),
		strings.Contains(errStr, "broken pipe"),
		strings.Contains(errStr, "eof"),
		strings.Contains(errStr, "unavailable"),
		strings.Contains(errStr, "transport is closing"),
		strings.Contains(errStr, "network unreachable"),
		strings.Contains(errStr, "no route to host"),
		strings.Contains(errStr, "i/o timeout"):
		return true
	}
	return false
}

// apiKey is the credential the agent presents now: APIKeyFile's content,
// read now, else APIKey.
func (a *agent) apiKey() (string, error) {
	if a.cfg.APIKeyFile == "" {
		return a.cfg.APIKey, nil
	}
	b, err := os.ReadFile(a.cfg.APIKeyFile)
	if err != nil {
		return "", fmt.Errorf("agent: read the credential file: %w", err)
	}
	key := strings.TrimSpace(string(b))
	if key == "" || strings.ContainsAny(key, " \t\r\n") {
		return "", fmt.Errorf("agent: %s: want one credential", a.cfg.APIKeyFile)
	}
	return key, nil
}
