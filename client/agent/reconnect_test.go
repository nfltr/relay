// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// fakeRelay is a Dispatcher that holds every ConnectHTTP stream open and
// reports each one on connected.
type fakeRelay struct {
	pb.UnimplementedDispatcherServer
	connected chan struct{}
	names     chan string // when set: each stream's x-agent-id
}

func (f *fakeRelay) ConnectHTTP(stream grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest]) error {
	if f.names != nil {
		md, _ := metadata.FromIncomingContext(stream.Context())
		f.names <- strings.Join(md.Get("x-agent-id"), ",")
	}
	_ = stream.SendHeader(metadata.Pairs("x-resolved-agent-id", "resolved")) // the agent reads the stream headers first
	f.connected <- struct{}{}
	<-stream.Context().Done()
	return nil
}

// startFakeRelay serves f on addr ("127.0.0.1:0" for any port) until stop.
func startFakeRelay(t *testing.T, addr string, f *fakeRelay) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDispatcherServer(srv, f)
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), srv.Stop
}

func waitConnected(t *testing.T, f *fakeRelay, within time.Duration, what string) time.Duration {
	t.Helper()
	start := time.Now()
	select {
	case <-f.connected:
		return time.Since(start)
	case <-time.After(within):
		t.Fatalf("%s: agent did not connect within %v", what, within)
		return 0
	}
}

// TestAgentReconnectsSoonAfterRelayRestart: a relay that restarts is back
// in well under a second; the agent must be too, not after a full
// --retry-wait (5 s by default: 6.7 s from restart to a working tunnel in
// the relay comparison benchmark). Retries: 1 also covers a reconnect
// attempt that gives up: the agent redials instead of running a
// connection cycle on the failed attempt's nil stream.
func TestAgentReconnectsSoonAfterRelayRestart(t *testing.T) {
	for _, retries := range []int{12, 1} {
		f := &fakeRelay{connected: make(chan struct{}, 4)}
		addr, stop := startFakeRelay(t, "127.0.0.1:0", f)
		ctx, cancel := context.WithCancel(context.Background())
		a := New(Config{ServerAddr: addr, AgentID: "reconnect", Retries: retries, Logger: slog.New(slog.DiscardHandler)})
		if err := a.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		waitConnected(t, f, 5*time.Second, "first connection")

		stop()                             // relay restart: down ...
		time.Sleep(400 * time.Millisecond) // ... and back 0.4 s later
		_, stop = startFakeRelay(t, addr, f)
		if took := waitConnected(t, f, 10*time.Second, "after restart"); took > 2*time.Second {
			t.Errorf("retries=%d: reconnected %v after the relay came back; want under 2 s", retries, took)
		}
		// The relay sees the stream before the agent has its answer: wait
		// for the agent's count.
		for deadline := time.Now().Add(5 * time.Second); a.Stats().GRPC.Conns != 1 && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		if st := a.Stats(); st.Reconnects.Lost+st.Reconnects.Drain+st.Reconnects.Move != 1 || st.GRPC.Conns != 1 {
			t.Errorf("retries=%d: reconnects %+v, relay connections %d: want the one restart, one connection", retries, st.Reconnects, st.GRPC.Conns)
		}
		cancel()
		<-a.Done()
		stop()
	}
}

// TestAgentReconnectsUnderItsName: the name an agent asks for (a machine's
// service) is what every connection sends, also after the relay resolved
// it to another id (its agent ref): a relay admits only a bound service
// as a name, so a reconnect under the resolved id would be refused.
func TestAgentReconnectsUnderItsName(t *testing.T) {
	f := &fakeRelay{connected: make(chan struct{}, 4), names: make(chan string, 4)}
	addr, stop := startFakeRelay(t, "127.0.0.1:0", f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := New(Config{ServerAddr: addr, AgentID: "svc", Retries: 12, Logger: slog.New(slog.DiscardHandler)})
	if err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	waitConnected(t, f, 5*time.Second, "first connection")
	stop()
	_, stop = startFakeRelay(t, addr, f)
	defer stop()
	waitConnected(t, f, 10*time.Second, "after restart")
	for i, want := range []string{"svc", "svc"} {
		if got := <-f.names; got != want {
			t.Fatalf("connection %d sent x-agent-id %q, want %q", i+1, got, want)
		}
	}
	if a.AgentID() != "resolved" {
		t.Fatalf("AgentID() = %q, want the relay's resolved id", a.AgentID())
	}
}

// tcpRelay is a fakeRelay that also holds every ConnectTCP stream open and
// reports each one on tcp.
type tcpRelay struct {
	fakeRelay
	tcp chan struct{}
}

func (f *tcpRelay) ConnectTCP(stream grpc.BidiStreamingServer[pb.TCPData, pb.TCPData]) error {
	f.tcp <- struct{}{}
	<-stream.Context().Done()
	return nil
}

// TestAgentTCPTunnelFollowsReconnect: after a reconnect the TCP tunnel
// runs on the new connection, not the closed one of the cycle before.
func TestAgentTCPTunnelFollowsReconnect(t *testing.T) {
	f := &tcpRelay{fakeRelay{connected: make(chan struct{}, 1000)}, make(chan struct{}, 1000)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve := func(ln net.Listener) func() {
		srv := grpc.NewServer()
		pb.RegisterDispatcherServer(srv, f)
		go func() { _ = srv.Serve(ln) }()
		return srv.Stop
	}
	stop := serve(ln)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := New(Config{ServerAddr: ln.Addr().String(), AgentID: "tcp-reconnect", TCPTunnel: true, Logger: slog.New(slog.DiscardHandler)})
	if err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	for _, what := range []string{"first connection", "after the restart"} {
		select {
		case <-f.tcp:
		case <-time.After(30 * time.Second): // a correctness bound: the stale client never gets one
			t.Fatalf("%s: no ConnectTCP stream", what)
		}
		if what == "first connection" {
			stop()
			if ln, err = net.Listen("tcp", ln.Addr().String()); err != nil {
				t.Fatal(err)
			}
			stop = serve(ln)
		}
	}
	cancel()
	<-a.Done()
	stop()
}
