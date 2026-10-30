// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/grpcclient"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
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
// RedialNow waits for the channel's state, not for a time: under load (a
// starved machine) a handshake slower than a fixed wait failed the attempt
// with the last dial's error ("connection refused").
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
	// Failed attempts until the channel's backoff is at its 1 s maximum: the
	// scenario, not the judgement.
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
	if st := conn.GetState(); st != connectivity.Ready {
		t.Fatalf("RedialNow returned with the channel %s; want READY: the relay is back", st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := health.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("first attempt after RedialNow: %v; want the relay that is back reached", err)
	}
}

// TestRedialNowOutlivesADialInFlight: a reset of the channel's backoff
// reaches only a backoff in progress. A dial in flight at RedialNow (it
// started before the relay was back: here one the "relay" accepts, holds and
// then drops) fails into a fresh backoff of up to 1.2 s, and the attempt
// failed at once with that dial's error. RedialNow waits for a dial made
// after it, however late the held dial fails.
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
	_, _ = health.Check(context.Background(), &healthpb.HealthCheckRequest{}) // refused: the channel backs off

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
	srv := grpc.NewServer(v1Relay())
	healthpb.RegisterHealthServer(srv, servingHealth{})
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()

	// The held dial fails once RedialNow has begun: the "relay" half-closes
	// it and sees the client close it.
	entered := &enteredCtx{Context: context.Background(), ch: make(chan struct{})}
	dropped := make(chan struct{})
	go func() {
		defer close(dropped)
		<-entered.ch
		_ = held.(*net.TCPConn).CloseWrite()
		_, _ = io.Copy(io.Discard, held)
	}()
	grpcclient.RedialNow(entered, conn)
	select {
	case <-entered.ch:
	default:
		t.Fatal("RedialNow returned without using its context: the held dial was never dropped")
	}
	<-dropped
	if st := conn.GetState(); st != connectivity.Ready {
		t.Fatalf("RedialNow returned with the channel %s; want READY: the relay is back", st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := health.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("first attempt after RedialNow: %v; want the relay that is back reached", err)
	}
}

// TestRedialNowReturnsWhileTheRelayIsDown: a relay still down refuses the
// dial RedialNow makes, and RedialNow returns then, so its caller's attempt
// fails with that refusal and the caller paces the next one itself.
func TestRedialNowReturnsWhileTheRelayIsDown(t *testing.T) {
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
	_, _ = health.Check(context.Background(), &healthpb.HealthCheckRequest{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	grpcclient.RedialNow(ctx, conn)
	if ctx.Err() != nil {
		t.Fatal("RedialNow waited out its caller's context on a relay that refuses its dial")
	}
}

// enteredCtx closes ch the first time its Done is called: when RedialNow
// begins to wait.
type enteredCtx struct {
	context.Context
	once sync.Once
	ch   chan struct{}
}

func (c *enteredCtx) Done() <-chan struct{} {
	c.once.Do(func() { close(c.ch) })
	return c.Context.Done()
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
