// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// Direct paths for capability-address sessions (direct_nf1.go; nfltr
// docs/decisions/nf1-direct-2026-11-14.md); the model's binding rows are
// direct_nf1_bindings_test.go.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// nf1Rig is an agent serving blob (an echo) under a capability address
// with a direct mode, and an anonymous client's DirectClient (no
// certificate), sessions on loopback pairs (the relay), direct
// connections on loopback UDP.
type nf1Rig struct {
	l    *linkSessions
	d    *DirectClient
	lis  *nf1.Listener
	mode DirectMode
	t    *testing.T
	mu   sync.Mutex
}

func nf1Table(t *testing.T, l *nf1.Listener, target string, mode DirectMode) *ServiceTable {
	t.Helper()
	table, err := NewServiceTable([]Service{{Name: "blob", Kind: agentservices.TCP, Target: target, E2EE: agentservices.E2EEOn, NF1: l, Direct: mode}})
	if err != nil {
		t.Fatal(err)
	}
	if d := table.direct; d != nil {
		d.ep.loopback = true
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = d.node.Drain(ctx)
			_ = d.ep.Close()
		})
	}
	return table
}

func newNF1Rig(t *testing.T, mode DirectMode) *nf1Rig {
	t.Helper()
	lis, _, err := nf1.Mint("relay.example")
	if err != nil {
		t.Fatal(err)
	}
	table := nf1Table(t, lis, echoTarget(t), mode)
	r := &nf1Rig{l: &linkSessions{ctx: t.Context(), targets: sessionTargets{services: table, agent: "web", qad: tunnelQAD(qadServer(t))},
		logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}, lis: lis, mode: mode, t: t}
	r.d, err = NewDirectClient(DirectClientConfig{QADTLS: func(string) *tls.Config { return &tls.Config{InsecureSkipVerify: true} }}) // #nosec G402 -- a test's relay
	if err != nil {
		t.Fatal(err)
	}
	r.d.ep.loopback = true
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = r.d.node.Drain(ctx)
		_ = r.d.ep.Close()
	})
	return r
}

// open is a relayed session to the address (the relay names the
// declaration's service), answered by the relay, the agent's answer frame
// not read.
func (r *nf1Rig) open(context.Context) (net.Conn, error) {
	s, c := sessionPair(r.t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: "blob", E2Ee: true, Answer: true})
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	l := r.l
	r.mu.Unlock()
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		return nil, fmt.Errorf("answer %v, %v", a, err)
	}
	return c, nil
}

// handshake opens a framed session, the address's TLS up, not Run.
func (r *nf1Rig) handshake(t *testing.T) (*DirectSession, *tls.Conn) {
	t.Helper()
	first, err := r.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	hints, err := nf1.ReadAnswer(first, r.lis.Address())
	if err != nil || !nf1.TakesDirect(hints) {
		t.Fatalf("answer hints %q, %v: want %q", hints, err, nf1.HintDirect)
	}
	ds := r.d.Start(first)
	tc, err := nf1.ClientTLS(t.Context(), ds.Conn(), r.lis.Address())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tc.Close()
		select {
		case <-ds.Done():
		case <-time.After(10 * time.Second):
			t.Error("the session did not end after its Close")
		}
	})
	return ds, tc
}

func (r *nf1Rig) run(t *testing.T, ds *DirectSession, tc *tls.Conn) chan PathEvent {
	t.Helper()
	events := make(chan PathEvent, 16)
	if err := ds.RunNF1(tc.ConnectionState(), NF1Route{Addr: r.lis.Address(), Open: r.open}, r.mode, func(e PathEvent) { events <- e }); err != nil {
		t.Fatal(err)
	}
	return events
}

// TestNF1DirectMovesAndFallsBack: a session to an address whose service
// takes direct paths moves to a punched direct connection mid-transfer
// (the agent's QAD address, the address's pinned key), then that
// connection dies and the session re-attaches relayed through a new open
// of the address: every byte back once, in order.
func TestNF1DirectMovesAndFallsBack(t *testing.T) {
	r := newNF1Rig(t, DirectOn)
	ds, tc := r.handshake(t)
	events := r.run(t, ds, tc)
	echo(t, tc, 4<<20, func() {
		if e := waitPath(t, events, PathDirect); !e.Peer.IsValid() {
			t.Fatalf("direct event without the peer's address: %+v", e)
		}
		p := r.d.nf1Pair(NF1Route{Addr: r.lis.Address()})
		p.mu.Lock()
		_ = p.q.CloseWithError(0, "the direct path dies")
		p.mu.Unlock()
		if e := waitPath(t, events, PathRelayed); e.Reason != ReasonDirectLost {
			t.Fatalf("fallback reason %q", e.Reason)
		}
	})
	if st := r.d.Stats(); st.DirectSent == 0 || st.RelayedSent == 0 || st.Punches["ok"] != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// TestNF1DirectOffStaysPlain: a listener without a direct mode answers no
// hint (the client keeps today's unframed session) and refuses a framed
// session.
func TestNF1DirectOffStaysPlain(t *testing.T) {
	r := newNF1Rig(t, DirectOff)
	if r.l.targets.services.direct != nil {
		t.Fatal("a table without a direct service has direct paths")
	}
	first, err := r.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if hints, err := nf1.ReadAnswer(first, r.lis.Address()); err != nil || len(hints) != 0 {
		t.Fatalf("hints %q, %v: want none", hints, err)
	}
	ds := r.d.Start(first)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := nf1.ClientTLS(ctx, ds.Conn(), r.lis.Address()); err == nil {
		t.Fatal("a listener without direct paths took a framed session")
	}
	plain, err := r.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tc, err := nf1.Handshake(t.Context(), plain, r.lis.Address())
	if err != nil {
		t.Fatal(err)
	}
	echo(t, tc.(*tls.Conn), 64<<10, func() {})
}

// TestNF1DirectContinueDropsReplacedAddress: a table that continues
// another's direct paths without its address resets that address's
// sessions (the revocation reaches the direct path too).
func TestNF1DirectContinueDropsReplacedAddress(t *testing.T) {
	r := newNF1Rig(t, DirectOn)
	ds, tc := r.handshake(t)
	events := r.run(t, ds, tc)
	waitPath(t, events, PathDirect)
	other, _, err := nf1.Mint("relay.example")
	if err != nil {
		t.Fatal(err)
	}
	next := nf1Table(t, other, echoTarget(t), DirectOn)
	next.Continue(r.l.targets.services)
	select {
	case <-ds.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the replaced address's session lives on")
	}
	same := nf1Table(t, r.lis, echoTarget(t), DirectOn)
	ds2, tc2 := r.handshake(t)
	r.run(t, ds2, tc2)
	same.Continue(next)
	echo(t, tc2, 64<<10, func() {})
}

// TestDirectStopDrainsThenResets (lane NF1FAULT, nfltr NAT lab
// nf1-revoke-TERM): a session on its direct path no longer holds the
// relayed stream the agent's drain counts, so a stopping agent must drain
// its direct sessions itself: stop waits while one lives, and once its
// drain ended resets each left (an ABORT on its path), so the peer ends at
// once instead of re-attaching to an agent that is gone until its detach
// bound (liveness + 30 s: measured 34 s in the lab).
func TestDirectStopDrainsThenResets(t *testing.T) {
	r := newNF1Rig(t, DirectOn)
	ds, tc := r.handshake(t)
	events := r.run(t, ds, tc)
	if _, err := tc.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	waitPath(t, events, PathDirect)
	drain, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() { r.l.targets.services.directServer().stop(drain); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("stop returned while a direct session lived and the drain ran")
	case <-time.After(300 * time.Millisecond):
	}
	start := time.Now()
	cancel() // the drain ends
	select {
	case <-ds.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the client's session lives on after the agent's stop")
	}
	if d := time.Since(start); d > directCutGrace {
		t.Errorf("the client's session ended %v after the stop, want within %v", d, directCutGrace)
	}
	if _, err := io.ReadAll(tc); err == nil {
		t.Error("the stopped session read a clean end, want a reset")
	}
	select {
	case <-stopped:
	case <-time.After(directCutGrace + time.Second):
		t.Fatal("stop did not return")
	}
}
