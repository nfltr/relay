// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/quic-go"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// testMachine is a client's DirectMachine of a testOrg: the chain to its
// root and the machine's name (nfltr's orgpki is the real one).
type testMachine struct {
	o    *testOrg
	cert tls.Certificate
}

func (m testMachine) Certificate() (*tls.Certificate, error) { return &m.cert, nil }

func (m testMachine) CheckServer(certs []*x509.Certificate, name string, now time.Time) (time.Time, error) {
	if len(certs) == 0 {
		return time.Time{}, errors.New("no certificate")
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: m.o.pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return time.Time{}, err
	}
	if certs[0].Subject.CommonName != name {
		return time.Time{}, fmt.Errorf("certificate of %q, want %q", certs[0].Subject.CommonName, name)
	}
	return certs[0].NotAfter, nil
}

// qadServer answers QAD on loopback as relay-core does: the observed
// address on one unidirectional stream.
func qadServer(t *testing.T) string {
	t.Helper()
	o := newTestOrg(t)
	cert := o.machine(t, "relay", nil, time.Hour, false)
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{QADALPN}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			q, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				s, err := q.OpenUniStream()
				if err == nil {
					_, _ = io.WriteString(s, q.RemoteAddr().String())
					_ = s.Close()
				}
				<-q.Context().Done()
			}()
		}
	}()
	return ln.Addr().String()
}

// directRig is an agent serving blob (an echo, direct mode) to db and a
// client of db with its DirectClient, sessions on loopback TCP pairs (the
// relay) and direct connections on loopback UDP.
type directRig struct {
	l      *linkSessions
	d      *DirectClient
	client testMachine
	mu     sync.Mutex
	conns  []net.Conn // the client ends of open's sessions
	table  func() *ServiceTable
	mode   DirectMode
	wrap   func(net.Conn) net.Conn // the client's end of a session, if set
}

func newDirectRig(t *testing.T, mode DirectMode) *directRig {
	t.Helper()
	o := newTestOrg(t)
	web := o.agentOrg(o.machine(t, "web", nil, time.Hour, false))
	target, qad := echoTarget(t), qadServer(t)
	mk := func() *ServiceTable {
		table, err := NewServiceTable([]Service{{Name: "blob", Kind: agentservices.TCP, Target: target, E2EE: agentservices.E2EEOn,
			Org: web, AllowGroups: []string{"db"}, Direct: mode}})
		if err != nil {
			t.Fatal(err)
		}
		if table.direct != nil {
			table.direct.ep.loopback = true
			table.direct.setRelay(qad, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- a test's relay
			d := table.direct
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = d.node.Drain(ctx)
				_ = d.ep.Close()
			})
		}
		return table
	}
	table := mk()
	r := &directRig{l: &linkSessions{ctx: t.Context(), targets: sessionTargets{services: table, agent: "web"}, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}},
		client: testMachine{o: o, cert: o.machine(t, "laptop", []string{"db"}, time.Hour, false)}, table: mk, mode: mode}
	var err error
	r.d, err = NewDirectClient(DirectClientConfig{Machine: r.client,
		Relayed: func(context.Context, string) (net.Conn, error) { return r.open(t, DirectServiceName) },
		QADTLS:  func(string) *tls.Config { return &tls.Config{InsecureSkipVerify: true} }}) // #nosec G402 -- a test's relay
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

// open is a relayed session to target, answered.
func (r *directRig) open(t *testing.T, target string) (net.Conn, error) {
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: target, E2Ee: true, Answer: true})
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
	r.mu.Lock()
	r.conns = append(r.conns, c)
	r.mu.Unlock()
	return c, nil
}

// session opens a framed session to blob, its TLS up and Run started;
// events gets its path changes.
func (r *directRig) session(t *testing.T) (*DirectSession, *tls.Conn, chan PathEvent) {
	t.Helper()
	ds, tc := r.handshake(t)
	events := make(chan PathEvent, 16)
	if err := ds.Run(tc.ConnectionState(), "web", "web", "blob", r.mode, func(e PathEvent) { events <- e }); err != nil {
		t.Fatal(err)
	}
	return ds, tc, events
}

// handshake opens a framed session to blob, its TLS up, not Run.
func (r *directRig) handshake(t *testing.T) (*DirectSession, *tls.Conn) {
	t.Helper()
	first, err := r.open(t, "blob")
	if err != nil {
		t.Fatal(err)
	}
	if r.wrap != nil {
		first = r.wrap(first)
	}
	ds := r.d.Start(first)
	cfg := r.d.punchTLS(&directPair{machine: "web"})
	BindServiceTLS(cfg, MachineALPN("web", "blob"))
	tc := tls.Client(ds.Conn(), cfg)
	if err := tc.HandshakeContext(t.Context()); err != nil {
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

func waitPath(t *testing.T, events chan PathEvent, path string) PathEvent {
	t.Helper()
	select {
	case e := <-events:
		if e.Path != path {
			t.Fatalf("path event %+v, want %s", e, path)
		}
		return e
	case <-time.After(15 * time.Second):
		t.Fatalf("no path event %s", path)
	}
	return PathEvent{}
}

// echo writes n random bytes through tc, its end after them, and checks
// the echo; mid runs once half went.
func echo(t *testing.T, tc *tls.Conn, n int, mid func()) {
	t.Helper()
	want := make([]byte, n)
	r := rand.New(rand.NewPCG(uint64(n), 7))
	for i := range want {
		want[i] = byte(r.Uint32())
	}
	var got []byte
	var rerr error
	var wg sync.WaitGroup
	wg.Go(func() { got, rerr = io.ReadAll(tc) })
	if _, err := tc.Write(want[:n/2]); err != nil {
		t.Fatal(err)
	}
	mid()
	if _, err := tc.Write(want[n/2:]); err != nil {
		t.Fatal(err)
	}
	_ = tc.CloseWrite()
	wg.Wait()
	if rerr != nil || !bytes.Equal(got, want) {
		t.Fatalf("echo: %d of %d bytes back: %v", len(got), n, rerr)
	}
}

// TestDirectSessionMovesAndFallsBack: an organisation-mode session that
// asked moves to a punched direct connection mid-transfer (the agent's
// address from QAD), then that connection dies and the session falls back
// to a relayed stream: every byte back once, in order.
func TestDirectSessionMovesAndFallsBack(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	ds, tc, events := r.session(t)
	echo(t, tc, 4<<20, func() {
		e := waitPath(t, events, PathDirect)
		if !e.Peer.IsValid() {
			t.Fatalf("direct event without the peer's address: %+v", e)
		}
		if ds.Path() != PathDirect {
			t.Fatalf("path %s", ds.Path())
		}
		p := r.d.pair("web", "web")
		p.mu.Lock()
		_ = p.q.CloseWithError(0, "the direct path dies")
		p.mu.Unlock()
		if e := waitPath(t, events, PathRelayed); e.Reason != ReasonDirectLost {
			t.Fatalf("fallback reason %q", e.Reason)
		}
	})
	st := r.d.Stats()
	if st.DirectSent == 0 || st.RelayedSent == 0 || st.Punches["ok"] != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// heldConn holds its writes once it read a byte (the agent's handshake
// flight) until release: the agent's end of the handshake waits, as on a
// starved agent, while this end's is over.
type heldConn struct {
	net.Conn
	mu              sync.Mutex
	armed, released bool
	held            [][]byte
}

func (h *heldConn) Read(p []byte) (int, error) {
	n, err := h.Conn.Read(p)
	if n > 0 {
		h.mu.Lock()
		h.armed = true
		h.mu.Unlock()
	}
	return n, err
}

func (h *heldConn) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.armed && !h.released {
		h.held = append(h.held, bytes.Clone(p))
		return len(p), nil
	}
	return h.Conn.Write(p)
}

func (h *heldConn) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, b := range h.held {
		_, _ = h.Conn.Write(b)
	}
	h.held, h.released = nil, true
}

// TestDirectOpenBeforeTheAgentsHandshake: a client's TLS 1.3 handshake ends
// a flight before the agent's, so its first direct OPEN can reach an agent
// that has not registered the session yet (a starved agent: CI relay
// a2a6b1de4, the first event relayed/direct_lost): the agent takes the
// OPEN once that handshake ends, never refuses it, and the session's first
// path event is direct.
func TestDirectOpenBeforeTheAgentsHandshake(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	h := &heldConn{}
	r.wrap = func(c net.Conn) net.Conn { h.Conn = c; return h }
	go func() { // the agent's handshake ends after the OPEN went
		for r.d.Stats().DirectSent == 0 && t.Context().Err() == nil {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // and after it arrived, on a loaded machine too
		h.release()
	}()
	_, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() { waitPath(t, events, PathDirect) })
}

// strangerTLS is the state of a TLS session no agent holds.
func strangerTLS(t *testing.T) tls.ConnectionState {
	t.Helper()
	cert := newTestOrg(t).machine(t, "stranger", nil, time.Hour, false)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() { _ = tls.Server(b, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake() }()
	c := tls.Client(a, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- a test's own session
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	return c.ConnectionState()
}

// TestDirectUnprovedMoveIsRefusedNotLost: a move whose direct stream the
// agent resets before its token (here a client token under a key no
// agent's session holds) never announced a direct path: its fallback
// reports refused_token, never direct_lost.
func TestDirectUnprovedMoveIsRefusedNotLost(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	r.d.detach = 2 * time.Second
	r.l.targets.services.direct.detach = 2 * time.Second // the agent's session ends too
	ds, _ := r.handshake(t)
	events := make(chan PathEvent, 16)
	if err := ds.Run(strangerTLS(t), "web", "web", "blob", r.mode, func(e PathEvent) { events <- e }); err != nil {
		t.Fatal(err)
	}
	if e := waitPath(t, events, PathRelayed); e.Reason != ReasonRefusedToken {
		t.Fatalf("reason %q, want %s", e.Reason, ReasonRefusedToken)
	}
	select {
	case <-ds.Done(): // its re-attaches are refused too: it ends after the detach bound
	case <-time.After(10 * time.Second):
		t.Fatal("the session re-attaches past its detach bound")
	}
	for range len(events) {
		if e := <-events; e.Path == PathDirect || e.Reason == ReasonDirectLost {
			t.Fatalf("path event %+v of a move never proved", e)
		}
	}
}

// TestDirectSessionRelayLostReattaches: a session's relayed stream (its
// fallback after the direct path died) is cut mid-transfer, as a relay
// reconnect cuts it: the session re-attaches on a new relayed stream once,
// every byte back once, in order.
func TestDirectSessionRelayLostReattaches(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	_, tc, events := r.session(t)
	echo(t, tc, 4<<20, func() {
		waitPath(t, events, PathDirect)
		p := r.d.pair("web", "web")
		p.mu.Lock()
		_ = p.q.CloseWithError(0, "the direct path dies")
		p.mu.Unlock()
		waitPath(t, events, PathRelayed)
		r.mu.Lock()
		_ = r.conns[len(r.conns)-1].Close()
		r.mu.Unlock()
		if e := waitPath(t, events, PathRelayed); e.Reason != ReasonRelayLost {
			t.Fatalf("reason %q", e.Reason)
		}
		select {
		case e := <-events:
			t.Fatalf("a second re-attach: %+v", e)
		case <-time.After(1500 * time.Millisecond):
		}
	})
}

// TestDirectSessionReattachesOnANewConnection: the agent's relay
// connection is replaced (nfltr builds a table per connection, Continue
// hands it the direct paths) and the session's relayed stream is cut
// with the old one: it re-attaches through the new connection, every byte
// back once, in order.
func TestDirectSessionReattachesOnANewConnection(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	_, tc, events := r.session(t)
	echo(t, tc, 4<<20, func() {
		waitPath(t, events, PathDirect)
		p := r.d.pair("web", "web")
		p.mu.Lock()
		_ = p.q.CloseWithError(0, "the direct path dies")
		p.mu.Unlock()
		waitPath(t, events, PathRelayed)
		next := r.table()
		next.Continue(r.l.targets.services)
		if next.direct != r.l.targets.services.direct {
			t.Fatal("Continue kept the new table's own direct paths")
		}
		r.mu.Lock()
		r.l = &linkSessions{ctx: t.Context(), targets: sessionTargets{services: next, agent: "web"}, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
		_ = r.conns[len(r.conns)-1].Close()
		r.mu.Unlock()
		if e := waitPath(t, events, PathRelayed); e.Reason != ReasonRelayLost {
			t.Fatalf("reason %q", e.Reason)
		}
		select {
		case e := <-events:
			t.Fatalf("a second re-attach: %+v", e)
		case <-time.After(1500 * time.Millisecond):
		}
	})
}

// TestDirectSessionReattachRefusedEnds: an agent that no longer holds a
// session resets every re-attach; the client's session ends after the
// detach bound instead of re-attaching forever.
func TestDirectSessionReattachRefusedEnds(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	r.d.detach = 2 * time.Second
	r.l.targets.services.direct.detach = 2 * time.Second // the agent's session ends too
	ds, _, events := r.session(t)
	waitPath(t, events, PathDirect)
	d := r.l.targets.services.direct
	d.mu.Lock()
	clear(d.sessions)
	d.mu.Unlock()
	p := r.d.pair("web", "web")
	p.mu.Lock()
	_ = p.q.CloseWithError(0, "the direct path dies")
	p.mu.Unlock()
	select {
	case <-ds.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the session re-attaches past its detach bound")
	}
	if n := len(events); n > 3 {
		t.Fatalf("%d re-attaches in 2 s, want at most one a second", n)
	}
}

// TestDirectSessionSlowRefusalsEnd: a path whose resets reach the client
// later than a second (a loaded machine, a slow relay) still ends a
// session whose agent refuses every re-attach after the detach bound: a
// stream counts as answered by its first byte, never by how long it took
// to die.
func TestDirectSessionSlowRefusalsEnd(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	r.d.detach = 2 * time.Second
	r.l.targets.services.direct.detach = 2 * time.Second
	r.d.cfg.Relayed = func(context.Context, string) (net.Conn, error) {
		c, err := r.open(t, DirectServiceName)
		return &slowReads{Conn: c, delay: 1500 * time.Millisecond}, err
	}
	ds, _, events := r.session(t)
	waitPath(t, events, PathDirect)
	d := r.l.targets.services.direct
	d.mu.Lock()
	clear(d.sessions)
	d.mu.Unlock()
	p := r.d.pair("web", "web")
	p.mu.Lock()
	_ = p.q.CloseWithError(0, "the direct path dies")
	p.mu.Unlock()
	select {
	case <-ds.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("slow refusals kept the session re-attaching past its detach bound")
	}
}

// slowReads delays a relayed stream's first read: its reset (or its
// first byte) reaches the client delay late.
type slowReads struct {
	net.Conn
	delay time.Duration
	once  sync.Once
}

func (c *slowReads) Read(p []byte) (int, error) {
	c.once.Do(func() { time.Sleep(c.delay) })
	return c.Conn.Read(p)
}

// TestDirectPairDeathBacksOffWhateverItsNoticeOrder: a pair whose
// connection died waits the first backoff before its next punch even
// when a try finds the dead connection before the death's own notice ran
// (the order a loaded runner showed: relay eb15a7a70594, a re-punch past
// a death and five refused re-attaches in 2 s).
func TestDirectPairDeathBacksOffWhateverItsNoticeOrder(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	ds, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() {
		waitPath(t, events, PathDirect)
		p := r.d.pair("web", "web")
		p.mu.Lock()
		q := p.q
		p.mu.Unlock()
		_ = q.CloseWithError(0, "the direct path dies")
		waitPath(t, events, PathRelayed) // the fallback, then the loop's try finds the death
		deadline := time.Now().Add(10 * time.Second)
		for {
			p.mu.Lock()
			noticed := p.q == nil
			if noticed { // the try that wins the race: the death's notice not yet run
				p.q, p.fails, p.next = q, 0, time.Time{}
			}
			p.mu.Unlock()
			if noticed {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the pair never noticed its connection's death")
			}
			time.Sleep(time.Millisecond)
		}
		before := r.d.Stats().Punches["ok"]
		if reason := ds.tryDirect(); reason != "backoff" {
			t.Errorf("a try past a death: %q, want backoff", reason)
		}
		if after := r.d.Stats().Punches["ok"]; after != before {
			t.Errorf("punched again past a death: %d punches, want %d", after, before)
		}
	})
}

// TestDirectSessionStaleStreamEndMovesNothing: a stream end whose session
// moved on since (another fallback, or a direct move, while it waited out
// the second) re-attaches nothing: one re-attach a second, whatever the
// ends' interleaving.
func TestDirectSessionStaleStreamEndMovesNothing(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	ds, _, events := r.session(t)
	waitPath(t, events, PathDirect)
	ds.mu.Lock()
	e := ds.epoch
	ds.mu.Unlock()
	if e == 0 {
		t.Fatal("the direct move recorded no epoch")
	}
	ds.fallback(e-1, nil)
	select {
	case ev := <-events:
		t.Fatalf("a stale stream end moved the session: %+v", ev)
	default:
	}
	if ds.Path() != PathDirect {
		t.Fatalf("path %s, want direct", ds.Path())
	}
}

// TestDirectServiceOff: a client that asks of a service without direct
// paths gets a relayed session, framed, and the reason off.
func TestDirectServiceOff(t *testing.T) {
	r := newDirectRig(t, DirectOff)
	r.mode = DirectOn // the client asks
	r.l.targets.services.direct = nil
	_, tc, events := r.session(t)
	if e := waitPath(t, events, PathRelayed); e.Reason != ReasonWithheld {
		t.Fatalf("reason %q, want %s (no reserved service)", e.Reason, ReasonWithheld)
	}
	echo(t, tc, 1<<20, func() {})
}

// TestParseDirectMode: true is on (LAN addresses included, owner
// 2026-11-11), public withholds them, lan is gone.
func TestParseDirectMode(t *testing.T) {
	for in, want := range map[string]DirectMode{"": DirectOff, "false": DirectOff, "true": DirectOn, "on": DirectOn, "public": DirectPublic} {
		if got, err := ParseDirectMode(in); err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseDirectMode("lan"); err == nil {
		t.Error("lan parsed")
	}
}
