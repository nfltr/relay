// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
	"github.com/nfltr/relay/client/dgram"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// udpEcho is a udp target that echoes each datagram and records, per
// payload, how often it came and from which source.
type udpEcho struct {
	pc net.PacketConn
	mu sync.Mutex
	n  map[string]int
	by map[string]bool // sources seen
}

func newUDPEcho(t *testing.T) *udpEcho {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	e := &udpEcho{pc: pc, n: map[string]int{}, by: map[string]bool{}}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			e.mu.Lock()
			e.n[string(buf[:n])]++
			e.by[from.String()] = true
			e.mu.Unlock()
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	return e
}

func (e *udpEcho) got(p string) int { e.mu.Lock(); defer e.mu.Unlock(); return e.n[p] }

func (e *udpEcho) sources() int { e.mu.Lock(); defer e.mu.Unlock(); return len(e.by) }

// countDirect counts the datagrams an association took from its direct
// path.
type countDirect struct {
	dgram.Direct
	in atomic.Int64
}

func (c *countDirect) OnDatagram(f func([]byte)) {
	c.Direct.OnDatagram(func(p []byte) { c.in.Add(1); f(p) })
}

// roundTrip sends p on f and waits for its echo.
func roundTrip(t *testing.T, f *dgram.Conn, p string) {
	t.Helper()
	_ = f.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := f.Write([]byte(p)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	n, err := f.Read(buf)
	if err != nil || string(buf[:n]) != p {
		t.Fatalf("echo of %.20q: %.20q %v", p, buf[:n], err)
	}
}

// TestDatagramDirectMovesAndFallsBack (nfltr
// docs/decisions/nf1-udp-2026-11-14.md "Flow moves between relayed and
// direct"): a udp service's association asks for direct paths; one flow's
// datagrams go relayed, then direct (QUIC datagrams, both ways) once the
// session moved, a datagram too large for a packet spills to the stream,
// and after the direct connection dies they go relayed again: every
// datagram reaches the target once (no duplicate: nothing was in flight
// at a move, so nothing lost) and from one agent socket throughout.
func TestDatagramDirectMovesAndFallsBack(t *testing.T) {
	target := newUDPEcho(t)
	r := newDirectRigOf(t, DirectOn, agentservices.UDP, target.pc.LocalAddr().String())
	ds, tc := r.handshake(t)
	cl := dgram.NewClient(tc, dgram.Config{})
	defer cl.Close() //nolint:errcheck
	cd := &countDirect{Direct: ds.Datagrams()}
	cl.SetDirect(cd)
	f, err := cl.Dial(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, f, "relayed-0")
	roundTrip(t, f, "relayed-1")

	events := make(chan PathEvent, 16)
	if err := ds.Run(tc.ConnectionState(), "web", "web", r.svc, DirectOn, func(e PathEvent) { events <- e }); err != nil {
		t.Fatal(err)
	}
	waitPath(t, events, PathDirect)
	for i := range 50 {
		roundTrip(t, f, fmt.Sprintf("direct-%d", i))
	}
	st := cl.Stats()
	if st.Direct < 50 || cd.in.Load() < 50 {
		t.Fatalf("on the direct path: %d sent, %d taken direct; want 50 each (stats %+v)", st.Direct, cd.in.Load(), st)
	}
	big := string(make([]byte, 4000)) // past one packet: the stream carries it
	roundTrip(t, f, big)
	if s := cl.Stats(); s.Spills != 1 {
		t.Fatalf("spills %d, want 1", s.Spills)
	}

	p := r.d.pair("web", "web")
	p.mu.Lock()
	_ = p.q.CloseWithError(0, "the direct path dies")
	p.mu.Unlock()
	if e := waitPath(t, events, PathRelayed); e.Reason != ReasonDirectLost {
		t.Fatalf("fallback reason %q", e.Reason)
	}
	direct := cl.Stats().Direct
	for i := range 5 {
		roundTrip(t, f, fmt.Sprintf("back-%d", i))
	}
	if d := cl.Stats().Direct; d != direct {
		t.Fatalf("%d datagrams direct after the fallback", d-direct)
	}

	for _, w := range []string{"relayed-0", "direct-0", "direct-49", big, "back-4"} {
		if n := target.got(w); n != 1 {
			t.Fatalf("the target got %.12q %d times, want once", w, n)
		}
	}
	if n := target.sources(); n != 1 {
		t.Fatalf("the target saw %d sources: one flow is one agent socket across moves", n)
	}
}

// dgUnit is an agent's direct path for one association, no client path
// layer: a session's server end on a direct stream (a quiclink session of
// a real connection with datagrams), the association's server with its
// direct datagrams, its client over a pipe, and the client's raw stream
// for frames: what a client sends, under any tag, at any time.
type dgUnit struct {
	c       *pathswitch.Conn
	sd      *sessionDatagrams
	client  *dgram.Client
	streams []*quiclink.Session // the client's ends, the first the session's
	target  *udpEcho
}

func newDGUnit(t *testing.T) *dgUnit {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	o := newTestOrg(t)
	srvTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{o.machine(t, "web", nil, time.Hour, false)},
		NextProtos: []string{quiclink.ALPN}}
	a, err := quiclink.New(quiclink.Config{PacketConn: pc, TLS: srvTLS, Datagrams: true, Liveness: link.LivenessFast,
		ServedPeer: func(*quic.Conn) (string, error) { return "laptop", nil }})
	if err != nil {
		t.Fatal(err)
	}
	b, err := quiclink.New(quiclink.Config{Datagrams: true, Liveness: link.LivenessFast,
		Dial: func(ctx context.Context, _ string, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, // #nosec G402 -- a test's own pair
				NextProtos: []string{quiclink.ALPN}}, qc)
		}})
	if err != nil {
		t.Fatal(err)
	}
	acc := make(chan *quiclink.Session, 2)
	go func() { _ = a.Serve(func(_ string, _ []byte, s peerlink.Session) { acc <- s.(*quiclink.Session) }) }()
	u := &dgUnit{target: newUDPEcho(t)}
	var served []*quiclink.Session
	for range 2 {
		s, err := b.Open(t.Context(), "web", nil)
		if err != nil {
			t.Fatal(err)
		}
		u.streams = append(u.streams, s.(*quiclink.Session))
		served = append(served, <-acc)
	}
	first := pathStream{Conn: served[0]}
	u.c = pathswitch.Server(first, PathDirect, pathswitch.Config{Detach: time.Second}) // an unanswered ABORT keeps the stream this long
	u.sd = &sessionDatagrams{c: u.c}
	u.sd.take(first, served[0], nil)
	// the second: a stream of the connection the session is not on (one
	// it left, another session's), its receiver this session's
	u.sd.take(pathStream{Conn: served[1]}, served[1], nil)
	session, assoc := net.Pipe()
	addr := u.target.pc.LocalAddr().(*net.UDPAddr)
	srv := dgram.NewServer(assoc, dgram.Config{}, func() (net.Conn, error) { return net.DialUDP("udp", nil, addr) })
	srv.SetDirect(u.sd)
	u.client = dgram.NewClient(session, dgram.Config{})
	t.Cleanup(func() {
		_ = u.client.Close()
		_ = srv.Close()
		u.c.Abort()
		for _, s := range append(u.streams, served...) {
			_ = s.Reset()
		}
		select {
		case <-u.c.Done():
		case <-time.After(5 * time.Second):
			t.Error("the session's path layer did not end")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = b.Drain(ctx)
		_ = a.Drain(ctx)
	})
	return u
}

// flow opens a flow (relayed, its O) and returns its id.
func (u *dgUnit) flow(t *testing.T) uint64 {
	t.Helper()
	f, err := u.client.Dial(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("open")) // its reply comes direct, to no one
	if !u.reaches("open", 5*time.Second) {
		t.Fatal("the flow's open did not reach the target")
	}
	return uint64(u.client.Stats().Flows)
}

// send sends p for flow id direct on the client's stream i (its tag).
func (u *dgUnit) send(t *testing.T, i int, id uint64, p string) {
	t.Helper()
	if err := u.streams[i].SendDatagram(append(binary.AppendUvarint(nil, id), p...)); err != nil {
		t.Fatal(err)
	}
}

// reaches: the target gets p within d.
func (u *dgUnit) reaches(p string, d time.Duration) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if u.target.got(p) > 0 {
			return true
		}
	}
	return false
}

// TestDatagramRevokeOnDirect (the model's direct-ignores-assoc, as a Go
// mutant: client/agent/testdata/direct_dgram_mutants.txt): once the
// agent reset the session (a revocation: its organisation's change, the
// nf1 address no longer served), no direct frame reaches the target,
// though the association's cleanup has not run yet and the direct stream
// still stands (its ABORT unanswered): the acceptance rule checks the
// session per frame.
func TestDatagramRevokeOnDirect(t *testing.T) {
	u := newDGUnit(t)
	id := u.flow(t)
	u.send(t, 0, id, "before")
	if !u.reaches("before", 5*time.Second) {
		t.Fatal("a direct frame of an open flow did not reach the target")
	}
	u.c.Abort() // the revocation's reset; the association still runs
	u.send(t, 0, id, "after")
	if u.reaches("after", 300*time.Millisecond) {
		t.Fatal("a direct frame reached the target after the session's reset")
	}
}
