// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/relay/client/dgram"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// TestDatagramDirectOnlyOnceTheAgentAttached (spec/DatagramAssoc.tla
// BindA, BindC, NoLostOnMove; mutant client-binds-first): while the agent
// has not attached the client's direct stream, the client sends no
// datagram direct and has not heard the agent's token (it is sent after
// the attach), so its first direct datagram after the move reaches the
// target. The agent's token went before its attach: the client went
// direct first and that datagram was dropped (relay 0424e437 under load,
// 4 of 300 runs: echo of "direct-0": i/o timeout).
func TestDatagramDirectOnlyOnceTheAgentAttached(t *testing.T) {
	target := newUDPEcho(t)
	r := newDirectRigOf(t, DirectOn, agentservices.UDP, target.pc.LocalAddr().String())
	ds, tc := r.handshake(t)
	cl := dgram.NewClient(tc, dgram.Config{})
	defer cl.Close() //nolint:errcheck
	cl.SetDirect(ds.Datagrams())
	f, err := cl.Dial(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, f, "relayed-0")

	entered, release := make(chan struct{}), make(chan struct{})
	hook := func() { close(entered); <-release }
	r.l.targets.services.direct.beforeAttach.Store(&hook)
	events := make(chan PathEvent, 16)
	if err := ds.Run(tc.ConnectionState(), "web", "web", r.svc, DirectOn, pathSink(events)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered: // the client moved: its OPEN is read, the attach held
	case <-time.After(10 * time.Second):
		t.Fatal("the agent never took the client's direct stream")
	}
	if err := ds.Datagrams().SendDatagram([]byte("early")); !errors.Is(err, dgram.ErrNotDirect) {
		close(release)
		t.Fatalf("a datagram sent direct before the agent attached: %v", err)
	}
	select {
	case e := <-events:
		close(release)
		t.Fatalf("the client went %s before the agent attached", e.Path)
	case <-time.After(time.Second): // the absence: what the old order failed at once
	}
	close(release)
	waitPath(t, events, PathDirect)
	roundTrip(t, f, "direct-0")
	if n := target.got("direct-0"); n != 1 {
		t.Fatalf("the target got the first direct datagram %d times", n)
	}
}

// TestDatagramAgentDirectOnceItHeardTheClient (spec/DatagramAssoc.tla
// ReplyA, aheard; mutant agent-sends-unheard): the agent sends a reply
// direct only once it took a client's frame on its current stream (the
// client then checked the agent's token, so it takes the reply); before,
// and after a frame under another stream's tag, the reply goes on the
// stream.
func TestDatagramAgentDirectOnceItHeardTheClient(t *testing.T) {
	u := newDGUnit(t)
	id := u.flow(t)
	if err := u.sd.SendDatagram([]byte("reply")); !errors.Is(err, dgram.ErrNotDirect) {
		t.Fatalf("the agent sent direct before it heard the client there: %v", err)
	}
	u.send(t, 1, id, "other tag")
	u.send(t, 0, id, "own tag")
	if !u.reaches("own tag", 5*time.Second) {
		t.Fatal("the client's direct frame did not reach the target")
	}
	if err := u.sd.SendDatagram([]byte("reply")); err != nil {
		t.Fatalf("the agent did not go direct once it heard the client: %v", err)
	}
}

// TestDatagramTargetEndsCleanlyAtTheClientsEnd: the client's end of a udp
// service's session (its END) ends the association, and the session ends
// clean, not reset. The target's end was closed whole (a pipe has no half
// close), so the direction from it read its own closed pipe, a failure:
// the session was reset and the agent's directSession lingered aborted
// until its detach bound (leakcheck: 41-64 registerSession goroutines per
// 300 runs of TestDatagramDirectMovesAndFallsBack).
func TestDatagramTargetEndsCleanlyAtTheClientsEnd(t *testing.T) {
	echo := newUDPEcho(t)
	target, _, err := dialDatagram(t.Context(), echo.pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck
	session, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() { joined <- peerlink.Join(session, target) }()
	_ = client.(*net.TCPConn).CloseWrite()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(client); err != nil {
		t.Fatalf("the session ended with %v, want a clean end", err)
	}
	if err := <-joined; err != nil {
		t.Fatalf("join: %v", err)
	}
}
