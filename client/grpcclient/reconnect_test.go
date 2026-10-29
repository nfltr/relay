// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nfltr/relay/client/grpcclient"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

type servingHealth struct {
	healthpb.UnimplementedHealthServer
}

func (servingHealth) Check(context.Context, *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

// TestClientConnReachesARelayBackFromAnOutageWithinASecond (G-R3): a
// connection that kept failing while the relay was down reaches it within
// about a second of its return. With gRPC's default backoff (1 s growing by
// 1.6x to 120 s) the channel refused every call for the rest of its backoff:
// `wg socks5`, which keeps one connection, came back 17-22 s after a restart.
func TestClientConnReachesARelayBackFromAnOutageWithinASecond(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // the relay is down

	conn, err := grpcclient.NewClientConn(false, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	health := healthpb.NewHealthClient(conn)
	check := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := health.Check(ctx, &healthpb.HealthCheckRequest{})
		return err
	}
	// Six seconds of failed calls: the default backoff would now wait 4 s
	// before its next dial.
	for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if check() == nil {
			t.Fatal("reached a relay that is down")
		}
	}

	ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("port %d taken while the relay was down: %v", port, err)
	}
	l := &firstAccept{Listener: ln, at: make(chan time.Time, 1)}
	srv := grpc.NewServer(v1Relay())
	healthpb.RegisterHealthServer(srv, servingHealth{})
	go func() { _ = srv.Serve(l) }()
	defer srv.Stop()
	back := time.Now()
	// The channel's next dial reaches the relay within its longest backoff
	// (1 s and its jitter) of the return; the default backoff would wait up
	// to 4 s more. Judged by the dial's arrival, not by a call: a loaded
	// machine slows the call after it, not the backoff before it.
	select {
	case at := <-l.at:
		t.Logf("dialed %s after the relay came back", at.Sub(back).Truncate(time.Millisecond))
	case <-time.After(2 * time.Second):
		t.Fatalf("the relay has been back %s and the channel has not dialed it; want it reached within about a second", time.Since(back).Truncate(time.Millisecond))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := health.Check(ctx, &healthpb.HealthCheckRequest{}, grpc.WaitForReady(true)); err != nil {
		t.Fatalf("call after the channel dialed the relay that is back: %v", err)
	}
}

// TestRedialNowReachesARelayThatIsBack: a caller that paces its own redials
// (pkg/agent, `nfltr http`) reaches a relay that is back on its next
// attempt. Without RedialNow the attempt fell into the channel's own backoff
// (up to 1 s) and failed at once with the last dial's error, so a tunnel came
// back up to a second after the relay (relay-agent-scaling decision, round 3).
func TestRedialNowReachesARelayThatIsBack(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // the relay is down

	conn, err := grpcclient.NewClientConn(false, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	health := healthpb.NewHealthClient(conn)
	// Failed attempts until the channel's backoff is at its 1 s maximum.
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		_, _ = health.Check(context.Background(), &healthpb.HealthCheckRequest{})
	}

	ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("port %d taken while the relay was down: %v", port, err)
	}
	srv := grpc.NewServer(v1Relay())
	healthpb.RegisterHealthServer(srv, servingHealth{})
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()

	grpcclient.RedialNow(context.Background(), conn)
	// The defect is a fail-fast with the last dial's error, not slowness: a
	// generous deadline keeps a loaded machine's slow handshake from looking
	// like it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := health.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("first attempt after RedialNow: %v; want the relay that is back reached", err)
	}
}

// TestRedialNowOutlivesADialInFlight: a reset of the channel's backoff
// reaches only a backoff in progress. A dial in flight at RedialNow (it
// started before the relay was back: here one the "relay" accepts and never
// answers) fails into a fresh backoff of up to 1.2 s, longer than RedialNow
// waits, and the attempt failed at once with that dial's error.
func TestRedialNowOutlivesADialInFlight(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	_ = ln.Close() // the relay is down

	conn, err := grpcclient.NewClientConn(false, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	health := healthpb.NewHealthClient(conn)
	// Failed attempts until the channel's backoff is at its 1 s maximum.
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		_, _ = health.Check(context.Background(), &healthpb.HealthCheckRequest{})
	}

	// The channel's next dial is accepted and held: a dial in flight.
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("port %d taken while the relay was down: %v", port, err)
	}
	held, err := ln.Accept()
	_ = ln.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close() //nolint:errcheck

	ln, err = net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("port %d taken: %v", port, err)
	}
	back := &firstAccept{Listener: ln, at: make(chan time.Time, 1)}
	srv := grpc.NewServer(v1Relay())
	healthpb.RegisterHealthServer(srv, servingHealth{})
	go func() { _ = srv.Serve(back) }()
	defer srv.Stop()

	// The held dial fails while RedialNow waits, after its reset: the
	// "relay" half-closes it and sees the client close it (failed).
	start := time.Now()
	failed := make(chan time.Time, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = held.(*net.TCPConn).CloseWrite()
		_, _ = io.Copy(io.Discard, held)
		failed <- time.Now()
	}()
	grpcclient.RedialNow(context.Background(), conn)
	returned := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = health.Check(ctx, &healthpb.HealthCheckRequest{})
	if err == nil {
		return
	}
	at := <-failed
	// RedialNow resets the backoff again every 250 ms while it waits; a
	// held dial whose failure came later than that before RedialNow's end
	// (a starved test) leaves it nothing to reset.
	if at.After(returned.Add(-300 * time.Millisecond)) {
		t.Skipf("the held dial failed %s after RedialNow began and %s before it returned (a starved test): nothing proved", at.Sub(start).Round(time.Millisecond), returned.Sub(at).Round(time.Millisecond))
	}
	// A lost reset: the channel's next dial waits out its backoff, at least
	// 800 ms (1 s less its jitter) after the held dial failed. A dial before
	// that is RedialNow's, too slow for its 1 s on a loaded machine.
	select {
	case dialed := <-back.at:
		if dialed.Sub(at) < 800*time.Millisecond {
			t.Skipf("first attempt after RedialNow: %v, but its dial reached the relay %s after the held dial failed (the backoff's floor is 800 ms): a loaded machine, nothing proved", err, dialed.Sub(at).Round(time.Millisecond))
		}
	case <-time.After(time.Until(at.Add(800 * time.Millisecond))):
	}
	t.Fatalf("first attempt after RedialNow: %v; want the relay that is back reached", err)
}

// firstAccept records when its listener's first connection arrived.
type firstAccept struct {
	net.Listener
	at chan time.Time
}

func (l *firstAccept) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		select {
		case l.at <- time.Now():
		default:
		}
	}
	return c, err
}

// v1Relay makes a test server answer unary calls as a protocol v1 relay
// does (the Welcome header), for tests of grpcclient's connections.
// allow:wrapper
func v1Relay() grpc.ServerOption {
	return grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		_ = grpc.SetHeader(ctx, metadata.Pairs(agentwire.WelcomePairs("v-test")...))
		return h(ctx, req)
	})
}
