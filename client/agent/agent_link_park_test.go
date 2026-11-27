// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// drainCount is a peerlink.Link that counts its drains.
type drainCount struct {
	peerlink.Link
	drains atomic.Int32
}

func (d *drainCount) Drain(context.Context) error { d.drains.Add(1); return nil }

// A primary's end parks its link for the next primary, which adopts it
// when the relay resumed it (the same bind token); another token, a second
// park, or the agent's stop drains it, and nothing is drained twice.
func TestLinkParkResumeOrDrain(t *testing.T) {
	ctx, stop := context.WithCancel(t.Context())
	p := newLinkPark(ctx)
	a, b := &drainCount{}, &drainCount{}
	p.park(parkedLink{token: "t1", node: a, acc: &linkAccept{}})
	if got := p.parked(); got != "t1" {
		t.Fatalf("parked %q, want t1", got)
	}
	p.park(parkedLink{token: "t2", node: b, acc: &linkAccept{}})
	if a.drains.Load() != 1 {
		t.Fatal("a link parked over another must drain the older")
	}
	z := &lazyLink{ctx: t.Context(), ls: &linkSessions{}}
	z.adopt(p.take())
	if z.node != b || z.token != "t2" || b.drains.Load() != 0 || p.parked() != "" {
		t.Fatalf("adopt: node %v token %q drains %d parked %q", z.node, z.token, b.drains.Load(), p.parked())
	}
	c := &drainCount{}
	p.park(parkedLink{token: "t3", node: c, acc: &linkAccept{}})
	stop()
	for deadline := time.Now().Add(5 * time.Second); c.drains.Load() == 0 && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
	} // context.AfterFunc runs in a goroutine of its own
	if c.drains.Load() != 1 {
		t.Fatal("the agent's stop must drain the parked link")
	}
	d := &drainCount{}
	p.park(parkedLink{token: "t4", node: d, acc: &linkAccept{}})
	if d.drains.Load() != 1 || p.parked() != "" {
		t.Fatal("a link parked after the agent stopped must drain at once")
	}
}

// A link that outlives its primary (parked, then resumed) serves the opens
// that come once the primary ended: its sessions dial their targets in the
// agent's context, not the primary's. An open in flight when the primary
// ended was refused (nfltr-relay's TestAgentLinkSurvivesReconnect).
func TestLinkSessionsDialPastThePrimary(t *testing.T) {
	primary, end := context.WithCancel(t.Context())
	ls := newLinkSessions(newLinkPark(t.Context()), primary, sessionTargets{forwardAddr: echoTarget(t)}, nil, slog.New(slog.DiscardHandler), &tcpStreamGrowth{})
	end()
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go ls.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("open after the primary ended: answer %v, %v; want accepted", a, err)
	}
}

// TestTCPTunnelReturnsAfterTheLinkIsParked: a primary whose stream ended
// returns from runTCPTunnel only once its up link is in the park, so the
// agent's next primary, which reads the park for its resume header, asks
// the relay to resume it (relay-core spec/README.md finding 43). Before,
// lazyLink.end ran in context.AfterFunc's goroutine and a fast reconnect
// asked for no resume: the relay closed the link under its sessions. The
// parked link answers an open (finding 42's case, here every run), and the
// next primary the relay resumed it to adopts it.
func TestTCPTunnelReturnsAfterTheLinkIsParked(t *testing.T) {
	r := newFakeLinkRelay(t)
	dial := r.dialer(TransportTCP)
	dial.park = newLinkPark(t.Context())
	logger, winner := linkWinner()
	target := echoServer(t)
	echo := func(what string) { t.Helper(); r.echo(t, what) }
	primary := func() (*chanStream, <-chan string) {
		st := newChanStream(t, 8, 64)
		relay := &primaryClient{st: st, md: metadata.Pairs(tcpBindHeader, testLinkToken, dataplane.AgentLinkHeader, "tcp")}
		parked := make(chan string, 1)
		go func() {
			_ = runTCPTunnel(t.Context(), relay, dial, t.Context(), sessionTargets{forwardAddr: target}, nil, logger, nil)
			parked <- dial.park.parked()
		}()
		return st, parked
	}
	st, parked := primary()
	st.in <- &pb.TCPData{SessionId: dataplane.AgentLinkSID, Data: []byte(dataplane.AgentLinkDial)}
	r.won(t, winner)
	echo("on the link") // its Node serves, so the lazyLink holds it
	st.closeIn()
	if got := <-parked; got != testLinkToken {
		t.Fatalf("parked %q when runTCPTunnel returned, want %q", got, testLinkToken)
	}
	echo("on the parked link")
	st, _ = primary() // the relay resumed the link: the same bind token
	for deadline := time.Now().Add(5 * time.Second); dial.park.parked() != ""; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the next primary did not adopt the parked link")
		}
	}
	echo("on the adopted link")
	st.closeIn()
}

// echo opens a session on the agent's link and echoes on it: the agent's
// Node serves, so its lazyLink holds the link (not only dialled it).
func (r *fakeLinkRelay) echo(t *testing.T, what string) {
	t.Helper()
	s := r.open(t, r.tcp, &pb.TCPData{TargetAddr: "x:1"})
	defer s.Close() //nolint:errcheck
	buf := []byte("ping")
	if _, err := s.Write(buf); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if _, err := io.ReadFull(s, buf); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// TestTCPTunnelLeavesTheParkToTheNextPrimary: a primary that ends before
// it read its response header leaves the parked link to the next primary
// (which asked to resume it) instead of taking and draining it (relay-core
// spec/README.md finding 44).
func TestTCPTunnelLeavesTheParkToTheNextPrimary(t *testing.T) {
	dial := RelayDialer{park: newLinkPark(t.Context())}
	drained := make(chan struct{})
	dial.park.park(parkedLink{token: testLinkToken, node: &drainSignal{c: drained}, acc: &linkAccept{}})
	st := newChanStream(t, 8, 64)
	gate := make(chan struct{})
	relay := &gatedClient{st: st, md: metadata.Pairs(tcpBindHeader, testLinkToken, dataplane.AgentLinkHeader, "tcp"), gate: gate}
	returned := make(chan struct{})
	go func() {
		_ = runTCPTunnel(t.Context(), relay, dial, t.Context(), sessionTargets{forwardAddr: echoServer(t)}, nil, slog.New(slog.DiscardHandler), nil)
		close(returned)
	}()
	st.closeIn() // the primary ends before its header arrives
	<-returned
	close(gate)
	select {
	case <-drained:
		t.Fatal("the ended primary drained the link the next primary resumes")
	case <-time.After(300 * time.Millisecond):
	}
	if got := dial.park.parked(); got != testLinkToken {
		t.Fatalf("parked %q, want %q", got, testLinkToken)
	}
}

// drainSignal is a peerlink.Link that closes c when drained.
type drainSignal struct {
	peerlink.Link
	c chan struct{}
}

func (d *drainSignal) Drain(context.Context) error { close(d.c); return nil }

// gatedClient is primaryClient whose stream's Header waits for gate.
type gatedClient struct {
	pb.DispatcherClient
	st   *chanStream
	md   metadata.MD
	gate chan struct{}
}

func (c *gatedClient) ConnectTCP(context.Context, ...grpc.CallOption) (pb.Dispatcher_ConnectTCPClient, error) {
	return &gatedStream{primaryStream: primaryStream{chanStream: c.st, md: c.md}, gate: c.gate}, nil
}

type gatedStream struct {
	primaryStream
	gate chan struct{}
}

// Header waits for gate in runTCPTunnel's header goroutine only: the
// stream's own reads of it (streamCredit, streamEndAck) go on, so the
// goroutine reads it after the stream ended.
func (s *gatedStream) Header() (metadata.MD, error) {
	if strings.Contains(string(debug.Stack()), "agent.runTCPTunnel.func") {
		<-s.gate
	}
	return s.md, nil
}

// TestTCPTunnelAdoptRefusedWhileDialling: a primary the relay resumed the
// parked link to, but that dials a link of its own first (the relay asked:
// the resumed link's connection dropped and a session waits), drains the
// parked link (lazyLink.adopt refused) and serves its sessions on the new
// one.
func TestTCPTunnelAdoptRefusedWhileDialling(t *testing.T) {
	r := newFakeLinkRelay(t)
	dial := r.dialer(TransportTCP)
	dial.park = newLinkPark(t.Context())
	logger, winner := linkWinner()
	target := echoServer(t)
	md := metadata.Pairs(tcpBindHeader, testLinkToken, dataplane.AgentLinkHeader, "tcp")
	run := func(relay pb.DispatcherClient) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			_ = runTCPTunnel(t.Context(), relay, dial, t.Context(), sessionTargets{forwardAddr: target}, nil, logger, nil)
			close(done)
		}()
		return done
	}
	st := newChanStream(t, 8, 64)
	done := run(&primaryClient{st: st, md: md})
	st.in <- &pb.TCPData{SessionId: dataplane.AgentLinkSID, Data: []byte(dataplane.AgentLinkDial)}
	r.won(t, winner)
	r.echo(t, "on the link") // bound, not only dialled: its primary's end parks it
	st.closeIn()
	<-done
	if got := dial.park.parked(); got != testLinkToken {
		t.Fatalf("parked %q, want %q", got, testLinkToken)
	}
	gate := make(chan struct{})
	st = newChanStream(t, 8, 64)
	run(&gatedClient{st: st, md: md, gate: gate})
	st.in <- &pb.TCPData{SessionId: dataplane.AgentLinkSID, Data: []byte(dataplane.AgentLinkDial)}
	r.won(t, winner) // the new primary's own link, dialled before it read the park
	close(gate)
	// Drained: the relay saw its connection end. (Its leaving the park is
	// not enough: until the relay's Node saw the drain, it could open the
	// session on the old connection, which the drain then reset.)
	select {
	case <-r.tcpDown:
	case <-time.After(time.Minute):
		t.Fatal("the parked link was not drained")
	}
	if got := dial.park.parked(); got != "" {
		t.Fatalf("parked %q after the drain, want none", got)
	}
	r.echo(t, "on the new primary's link")
	st.closeIn()
}

// TestLazyAgentLinkGivesUp: a link that cannot connect is not dialled
// again on this primary, and its sessions stay on the gRPC streams.
func TestLazyAgentLinkGivesUp(t *testing.T) {
	var dials atomic.Int32
	dial := RelayDialer{Transport: TransportTCP, Data: func(context.Context) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("connection refused")
	}}
	md := metadata.Pairs(tcpBindHeader, testLinkToken, dataplane.AgentLinkHeader, "tcp")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ls := &linkSessions{ctx: ctx, logger: slog.New(slog.DiscardHandler)}
	z := newLazyLink(ctx, dial, func() (metadata.MD, error) { return md, nil }, ls, slog.New(slog.DiscardHandler))
	defer func() { cancel(); z.end() }()
	z.control(dataplane.AgentLinkDial)
	select {
	case <-z.failed:
	case <-time.After(10 * time.Second):
		t.Fatal("the failed dial did not give up")
	}
	z.control(dataplane.AgentLinkDial)
	z.mu.Lock()
	dialing := z.dialing
	z.mu.Unlock()
	if n := dials.Load(); n != 1 || dialing {
		t.Fatalf("%d dials, want 1: a link that failed is not tried again on its primary", n)
	}
}
