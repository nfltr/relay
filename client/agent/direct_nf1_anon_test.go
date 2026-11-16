// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// Sessions to an address served with no account (nf1.HintAnonymous; nfltr
// docs/decisions/nf1-anon-2026-11-16.md section 2): direct only.

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/client/nf1"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// newNF1AnonRig is newNF1Rig for an anonymous listener whose service is a
// queue (its Accept is the service's first byte), the client's direct-path
// bound and the agent's detach bound short.
func newNF1AnonRig(t *testing.T) (*nf1Rig, *SessionQueue) {
	t.Helper()
	l, _, err := nf1.Mint("relay.example")
	if err != nil {
		t.Fatal(err)
	}
	if l, err = l.WithAnonymous(); err != nil {
		t.Fatal(err)
	}
	q := NewSessionQueue(4)
	t.Cleanup(func() { _ = q.Close() })
	table, err := NewServiceTable([]Service{{Name: "blob", Kind: agentservices.TCP, Queue: q, E2EE: agentservices.E2EEOn, NF1: l, Direct: DirectOn}})
	if err != nil {
		t.Fatal(err)
	}
	d := table.direct
	d.ep.loopback, d.detach = true, time.Second
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = d.node.Drain(ctx)
		_ = d.ep.Close()
	})
	r := &nf1Rig{l: &linkSessions{ctx: t.Context(), targets: sessionTargets{services: table, agent: "web", qad: tunnelQAD(qadServer(t))},
		logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}, lis: l, mode: DirectOn, t: t}
	r.d, err = NewDirectClient(DirectClientConfig{QADTLS: func(string) *tls.Config { return &tls.Config{InsecureSkipVerify: true} }}) // #nosec G402 -- a test's relay
	if err != nil {
		t.Fatal(err)
	}
	r.d.ep.loopback, r.d.anonBound, r.d.detach = true, 2*time.Second, 2*time.Second
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = r.d.node.Drain(ctx)
		_ = r.d.ep.Close()
	})
	return r, q
}

// marks counts the relayed opens of a session's direct paths by their
// first byte (C: a control exchange, A: a re-attach).
type marks struct{ control, attach atomic.Int32 }

func (m *marks) open(r *nf1Rig) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		c, err := r.open(ctx)
		if err != nil {
			return nil, err
		}
		return &markConn{Conn: c, m: m}, nil
	}
}

type markConn struct {
	net.Conn
	m    *marks
	seen bool
}

func (c *markConn) Write(p []byte) (int, error) {
	if !c.seen && len(p) > 0 {
		c.seen = true
		switch p[0] {
		case nf1MarkControl:
			c.m.control.Add(1)
		case nf1MarkAttach:
			c.m.attach.Add(1)
		}
	}
	return c.Conn.Write(p)
}

// nextSession is the queue's next session within d, nil if none.
func nextSession(q *SessionQueue, d time.Duration) net.Conn {
	got := make(chan net.Conn, 1)
	go func() {
		c, err := q.Accept()
		if err == nil {
			got <- c
		}
	}()
	select {
	case c := <-got:
		return c
	case <-time.After(d):
		return nil
	}
}

// TestNF1AnonDirectRequired: a session to an address served with no
// account sends no byte of the service before its direct path. Punch
// blocked (the agent's direct socket gone): WaitDirect fails
// nf1.ErrDirectRequired at the client's bound, before any byte reached the
// service (its queue took no session). Path dropped mid-session: the
// session ends with the same error, with no relayed re-attach (no A), and
// the service's session reads relay ERROR_REASON_ACCOUNT_REQUIRED.
func TestNF1AnonDirectRequired(t *testing.T) {
	t.Run("punch blocked", func(t *testing.T) {
		r, q := newNF1AnonRig(t)
		_ = r.l.targets.services.direct.ep.Close() // no candidate of the agent's answers
		ds, tc := r.handshake(t)
		var m marks
		if err := ds.RunNF1(tc.ConnectionState(), NF1Route{Addr: r.lis.Address(), Open: m.open(r), Anonymous: true}, DirectOn, nil); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		start := time.Now()
		if err := ds.WaitDirect(ctx); !errors.Is(err, nf1.ErrDirectRequired) {
			t.Fatalf("WaitDirect = %v, want ErrDirectRequired", err)
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Fatalf("gave up after %v, past the bound", el)
		}
		if c := nextSession(q, 500*time.Millisecond); c != nil {
			t.Fatal("the service took a session that never went direct")
		}
		if m.attach.Load() != 0 {
			t.Fatalf("%d relayed re-attaches", m.attach.Load())
		}
	})
	t.Run("path dropped", func(t *testing.T) {
		r, q := newNF1AnonRig(t)
		ds, tc := r.handshake(t)
		var m marks
		if err := ds.RunNF1(tc.ConnectionState(), NF1Route{Addr: r.lis.Address(), Open: m.open(r), Anonymous: true}, DirectOn, nil); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		if err := ds.WaitDirect(ctx); err != nil {
			t.Fatalf("WaitDirect = %v", err)
		}
		srv := nextSession(q, 10*time.Second)
		if srv == nil {
			t.Fatal("the service took no session once it was direct")
		}
		if _, err := tc.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := io.ReadFull(srv, b); err != nil || string(b) != "ping" {
			t.Fatalf("service read %q, %v", b, err)
		}
		p := r.d.nf1Pair(NF1Route{Addr: r.lis.Address()})
		p.mu.Lock()
		_ = p.q.CloseWithError(0, "the direct path dies")
		p.mu.Unlock()
		for end := time.Now().Add(10 * time.Second); ds.Err() == nil && time.Now().Before(end); {
			time.Sleep(20 * time.Millisecond)
		}
		if !errors.Is(ds.Err(), nf1.ErrDirectRequired) {
			t.Fatalf("session error %v, want ErrDirectRequired", ds.Err())
		}
		if _, err := tc.Read(b); err == nil {
			t.Fatal("the session reads on with no direct path")
		}
		if m.attach.Load() != 0 {
			t.Fatalf("%d relayed re-attaches", m.attach.Load())
		}
		_ = srv.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := srv.Read(b)
		a, ok := errors.AsType[*link.Abort](err)
		if reason, rok := dataplane.AbortReason(a); !ok || !rok || reason != relayv1.ErrorReason_ERROR_REASON_ACCOUNT_REQUIRED {
			t.Fatalf("service read %v, want ERROR_REASON_ACCOUNT_REQUIRED", err)
		}
	})	// A client that ignores a1 and runs a plain session (unframed: it
	// could never leave the relay) is refused by the agent too: no TLS, no
	// session of the service.
	t.Run("plain refused", func(t *testing.T) {
		r, q := newNF1AnonRig(t)
		plain, err := r.open(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nf1.ReadAnswer(plain, r.lis.Address()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if _, err := nf1.ClientTLS(ctx, plain, r.lis.Address()); err == nil {
			t.Fatal("an anonymous listener took a plain session")
		}
		if c := nextSession(q, 500*time.Millisecond); c != nil {
			t.Fatal("the service took a plain session")
		}
	})
}
