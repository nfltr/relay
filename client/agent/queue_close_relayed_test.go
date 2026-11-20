// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/nfltr/link"
)

// Lane RELAYCLOSE (link spec/RelayedClose.tla CloseTruth, mutant
// close-before-ack): an accepted relayed session's Close returns once the
// relay's Mux read every byte and the end, so a program that exits then
// loses nothing; before, it returned at once.

// relayGate holds its reads, once armed, until open is closed: the
// relay's Mux reads nothing meanwhile.
type relayGate struct {
	net.Conn
	armed *atomic.Bool
	open  chan struct{}
}

func (c relayGate) Read(b []byte) (int, error) {
	if c.armed.Load() {
		<-c.open
	}
	return c.Conn.Read(b)
}

// relayedSession is an agent-link session whose relay end reads what the
// agent sends (got: all of it, at its end) once the returned gate opens.
func relayedSession(t *testing.T) (s *link.Session, gate chan struct{}, got <-chan []byte) {
	t.Helper()
	a, b := net.Pipe()
	gate = make(chan struct{})
	armed := new(atomic.Bool)
	read := make(chan []byte, 1)
	ctx := context.Background()
	go func() {
		c, _, err := link.Server(ctx, relayGate{Conn: b, armed: armed, open: gate}, link.Config{Auth: link.NoAuth})
		if err != nil {
			return
		}
		m := link.NewMux(c)
		t.Cleanup(func() { _ = m.Close() })
		_ = m.Serve(func(_ []byte, s *link.Session) {
			bs, _ := io.ReadAll(s)
			_ = s.Close()
			read <- bs
		})
	}()
	c, err := link.Client(ctx, a, link.Config{})
	if err != nil {
		t.Fatal(err)
	}
	m := link.NewMux(c)
	go func() { _ = m.Serve(nil) }()
	t.Cleanup(func() { _ = m.Close() })
	if s, err = m.Open([]byte("relay")); err != nil {
		t.Fatal(err)
	}
	if err = s.Sync(); err != nil { // the relay took the open
		t.Fatal(err)
	}
	armed.Store(true)
	return s, gate, read
}

func TestQueueRelayedCloseWaitsForTheRelay(t *testing.T) {
	user, agentEnd := queuedPair(t)
	s, gate, got := relayedSession(t)
	go func() { _ = joinTarget(s, ackerOf(s), agentEnd) }()
	if _, err := user.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	ret := closeAsync(user)
	notYet(t, ret)
	close(gate)
	waitRet(t, ret, nil)
	if b := <-got; string(b) != "tail" {
		t.Fatalf("the relay read %q, want the tail", b)
	}
}

// TestQueueRelayedPeerCloseThenCloseIsNil: the relay's peer closes the
// session whole (a dialler's Close); Accept's conn reads EOF and closes
// with nothing left to send: nil (nettest BasicIO through relay-core),
// not the reset an unreported end gives.
func TestQueueRelayedPeerCloseThenCloseIsNil(t *testing.T) {
	user, agentEnd := queuedPair(t)
	a, b := net.Pipe()
	ctx := context.Background()
	go func() {
		c, _, err := link.Server(ctx, b, link.Config{Auth: link.NoAuth})
		if err != nil {
			return
		}
		m := link.NewMux(c)
		t.Cleanup(func() { _ = m.Close() })
		_ = m.Serve(func(_ []byte, s *link.Session) {
			_, _ = s.Write([]byte("bye"))
			_ = s.Close()
		})
	}()
	c, err := link.Client(ctx, a, link.Config{})
	if err != nil {
		t.Fatal(err)
	}
	m := link.NewMux(c)
	go func() { _ = m.Serve(nil) }()
	t.Cleanup(func() { _ = m.Close() })
	s, err := m.Open([]byte("relay"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = joinTarget(s, ackerOf(s), agentEnd) }()
	if b, err := io.ReadAll(user); err != nil || string(b) != "bye" {
		t.Fatalf("read %q, %v", b, err)
	}
	waitRet(t, closeAsync(user), nil)
}
