// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/nettest"
)

// The invariants of spec/DatagramAssoc.tla, one Go test each, on a client
// and an agent joined by an in-memory stream.

func addr(s string) net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: len(s)} }

// echo is a UDP target that answers each datagram n times with it.
func echo(t *testing.T, n int) (*net.UDPAddr, *atomic.Int64) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var got atomic.Int64
	go func() {
		buf := make([]byte, MaxDatagram)
		for {
			k, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got.Add(1)
			for range n {
				_, _ = pc.WriteToUDP(buf[:k], from)
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr), &got
}

func dialUDP(to *net.UDPAddr) Dial {
	return func() (net.Conn, error) { return net.DialUDP("udp", nil, to) }
}

// pair is a client and an agent of one association over net.Pipe.
func pair(t *testing.T, ccfg, acfg Config, dial Dial) (*Client, *Server) {
	t.Helper()
	c1, c2 := net.Pipe()
	s := NewServer(c2, acfg, dial)
	c := NewClient(c1, ccfg)
	t.Cleanup(func() { _ = c.Close(); _ = s.Close(); <-c.Done(); <-s.Done() })
	return c, s
}

func recvFlow(c *Client) (*Flow, chan []byte, chan Reason) {
	in, closed := make(chan []byte, 64), make(chan Reason, 1)
	f, err := c.Open(FlowOptions{Deliver: func(p []byte) {
		select {
		case in <- append([]byte(nil), p...):
		default:
		}
	}, Closed: func(r Reason) { closed <- r }})
	if err != nil {
		panic(err)
	}
	return f, in, closed
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func recv(t *testing.T, ch chan []byte) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(10 * time.Second):
		t.Fatal("no datagram")
		return nil
	}
}

func TestDatagramAssocEcho(t *testing.T) {
	to, _ := echo(t, 1)
	c, s := pair(t, Config{}, Config{}, dialUDP(to))
	f, in, _ := recvFlow(c)
	for i, size := range []int{0, 1, 1200, 1232, 1400, 8192} /* darwin's udp maxdgram is 9216 */ {
		p := bytes.Repeat([]byte{byte(i)}, size)
		f.Send(p)
		if got := recv(t, in); !bytes.Equal(got, p) {
			t.Fatalf("size %d: got %d bytes", size, len(got))
		}
	}
	if st := s.Stats(); st.Flows != 1 || st.Live != 1 {
		t.Fatalf("agent stats %+v", st)
	}
}

// rawAgent drives the agent with frames written by hand, reading its
// answers.
type rawAgent struct {
	w  net.Conn
	r  *bufio.Reader
	s  *Server
	mu sync.Mutex
}

func newRawAgent(t *testing.T, cfg Config, dial Dial) *rawAgent {
	c1, c2 := net.Pipe()
	s := NewServer(c2, cfg, dial)
	t.Cleanup(func() { _ = c1.Close(); <-s.Done() })
	return &rawAgent{w: c1, r: bufio.NewReader(c1), s: s}
}

func (r *rawAgent) send(t *testing.T, fs ...frame) {
	t.Helper()
	var b []byte
	for _, f := range fs {
		b = appendFrame(b, f)
	}
	go func() { _, _ = r.w.Write(b) }()
}

func (r *rawAgent) next(t *testing.T) frame {
	t.Helper()
	_ = r.w.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := readFrame(r.r, make([]byte, MaxDatagram))
	if err != nil {
		t.Fatal(err)
	}
	f.payload = append([]byte(nil), f.payload...)
	return f
}

// NoDeliverAfterClose: a datagram for a flow the agent closed is dropped
// (counted), never written to the target; at the client, a flow's Send
// after its Close is dropped.
func TestDatagramAssocNoDeliverAfterClose(t *testing.T) {
	to, got := echo(t, 0)
	r := newRawAgent(t, Config{}, dialUDP(to))
	r.send(t, frame{typ: frameOpen, id: 1, payload: []byte("a")}, frame{typ: frameData, id: 1, payload: []byte("b")},
		frame{typ: frameClose, id: 1, reason: ReasonIdle}, frame{typ: frameData, id: 1, payload: []byte("late")})
	if f := r.next(t); f.typ != frameAccept || f.id != 1 {
		t.Fatalf("got %+v", f)
	}
	waitFor(t, "the late datagram's drop", func() bool { return r.s.Stats().Closed == 1 })
	time.Sleep(50 * time.Millisecond)
	if got.Load() != 2 {
		t.Fatalf("target got %d datagrams, want 2", got.Load())
	}
	c, _ := pair(t, Config{}, Config{}, dialUDP(to))
	f, _, _ := recvFlow(c)
	f.Send([]byte("x"))
	_ = f.Close()
	if f.Send([]byte("y")) || c.Stats().Closed != 1 {
		t.Fatal("a send after Close was taken")
	}
}

// NoCrossFlow: each flow gets its own target socket's replies only.
func TestDatagramAssocNoCrossFlow(t *testing.T) {
	to, _ := echo(t, 1)
	c, _ := pair(t, Config{}, Config{}, dialUDP(to))
	var flows []*Flow
	var ins []chan []byte
	for range 8 {
		f, in, _ := recvFlow(c)
		flows, ins = append(flows, f), append(ins, in)
	}
	for round := range 20 {
		for i, f := range flows {
			f.Send(fmt.Appendf(nil, "%d/%d", i, round))
		}
		for i, in := range ins {
			if p := recv(t, in); string(p) != fmt.Sprintf("%d/%d", i, round) {
				t.Fatalf("flow %d got %q", i, p)
			}
		}
	}
}

// ClosedFinal: the agent refuses an open at or below the highest id it
// saw, so an id is never reused in an association; a datagram for an id
// never opened ends the association.
func TestDatagramAssocClosedFinal(t *testing.T) {
	to, _ := echo(t, 0)
	r := newRawAgent(t, Config{}, dialUDP(to))
	r.send(t, frame{typ: frameOpen, id: 2, payload: []byte("a")}, frame{typ: frameOpen, id: 1, payload: []byte("b")},
		frame{typ: frameOpen, id: 2, payload: []byte("c")})
	for _, want := range []frame{{typ: frameAccept, id: 2}, {typ: frameRefuse, id: 1, reason: ReasonClosed}, {typ: frameRefuse, id: 2, reason: ReasonClosed}} {
		if f := r.next(t); f.typ != want.typ || f.id != want.id || f.reason != want.reason {
			t.Fatalf("got %+v, want %+v", f, want)
		}
	}
	r.send(t, frame{typ: frameData, id: 9, payload: []byte("x")})
	select {
	case <-r.s.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("a datagram for an unopened id did not end the association")
	}
	if !errors.Is(r.s.a.errNow(), ErrProtocol) {
		t.Fatalf("err %v", r.s.a.errNow())
	}
}

// TableBounded: each side's cap, set independently: past the client's an
// Open fails, past the agent's the open is refused (R) and the flow ends.
func TestDatagramAssocTableBounded(t *testing.T) {
	to, _ := echo(t, 1)
	c, s := pair(t, Config{MaxFlows: 3}, Config{MaxFlows: 2}, dialUDP(to))
	var closed []chan Reason
	for range 3 {
		f, in, cl := recvFlow(c)
		f.Send([]byte("x"))
		closed = append(closed, cl)
		_ = in
	}
	if r := <-closed[2]; r != ReasonFull {
		t.Fatalf("third flow ended %v, want refused full", r)
	}
	if _, err := c.Open(FlowOptions{}); err != nil {
		t.Fatalf("a slot freed by the refusal: %v", err)
	}
	if _, err := c.Open(FlowOptions{}); !errors.Is(err, ErrFlowsFull) {
		t.Fatalf("past the client's cap: %v", err)
	}
	if st := s.Stats(); st.Live != 2 || st.FlowsFull != 1 {
		t.Fatalf("agent %+v", st)
	}
}

// blockedStream is a stream whose writes wait forever (no credit).
type blockedStream struct{ done chan struct{} }

func (b blockedStream) Read([]byte) (int, error)  { <-b.done; return 0, net.ErrClosed }
func (b blockedStream) Write([]byte) (int, error) { <-b.done; return 0, net.ErrClosed }
func (b blockedStream) Close() error {
	select {
	case <-b.done:
	default:
		close(b.done)
	}
	return nil
}

// MemoryBound and NoHOL at the client: with no stream credit, each flow
// queues at most QueueLen datagrams; Send never waits, and another flow
// still queues its own.
func TestDatagramAssocMemoryBound(t *testing.T) {
	c := NewClient(blockedStream{make(chan struct{})}, Config{QueueLen: 8})
	defer c.Close()
	a, _ := c.Open(FlowOptions{})
	b, _ := c.Open(FlowOptions{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			a.Send([]byte("a"))
		}
		if !b.Send([]byte("b")) {
			t.Error("a full flow's queue kept another flow's datagram out")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Send waited")
	}
	// The sender took one batch before it blocked: at most 2 x QueueLen of a's.
	if st := c.Stats(); st.QueueFull < 1000-2*8 {
		t.Fatalf("queue full drops %d", st.QueueFull)
	}
}

// stuck is a target that never reads.
type stuck struct {
	net.Conn
	done chan struct{}
}

func (s stuck) Write([]byte) (int, error) { <-s.done; return 0, net.ErrClosed }
func (s stuck) Read([]byte) (int, error)  { <-s.done; return 0, net.ErrClosed }
func (s stuck) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}

// NoHOL at the agent: a target that takes nothing fills only its own
// flow's queue (counted TargetFull); another flow is served.
func TestDatagramAssocNoHOL(t *testing.T) {
	to, _ := echo(t, 1)
	var n atomic.Int32
	dial := func() (net.Conn, error) {
		if n.Add(1) == 1 {
			return stuck{done: make(chan struct{})}, nil
		}
		return net.DialUDP("udp", nil, to)
	}
	c, s := pair(t, Config{}, Config{QueueLen: 4}, dial)
	bad, _, _ := recvFlow(c)
	good, in, _ := recvFlow(c)
	for i := range 200 {
		bad.Send([]byte("stuck"))
		good.Send(fmt.Appendf(nil, "%d", i))
		if p := recv(t, in); string(p) != fmt.Sprint(i) {
			t.Fatalf("got %q", p)
		}
	}
	if s.Stats().TargetFull == 0 {
		t.Fatal("no TargetFull drop")
	}
}

// NoReflection: a source the listener does not admit is dropped before
// any lookup: no association opened, nothing written to it.
func TestDatagramAssocNoReflection(t *testing.T) {
	var dials atomic.Int32
	var wrote atomic.Int32
	allowed := netip.MustParsePrefix("10.0.0.0/8")
	fw := NewForwarder(ForwarderConfig{Allow: allowed.Contains},
		func(context.Context) (*Client, error) { dials.Add(1); return nil, errors.New("no") },
		func([]byte, netip.AddrPort) { wrote.Add(1) })
	fw.Handle(context.Background(), netip.MustParseAddrPort("192.0.2.1:53"), []byte("spoofed"))
	if dials.Load() != 0 || wrote.Load() != 0 || fw.Stats().SourceRefused != 1 {
		t.Fatalf("dials %d wrote %d stats %+v", dials.Load(), wrote.Load(), fw.Stats())
	}
}

// AmpBound: a target answering ten times what it gets is cut to Ratio x
// the source's bytes + Burst, per source address: a new flow from it (a
// new port) does not reset the budget.
func TestDatagramAssocAmpBound(t *testing.T) {
	to, _ := echo(t, 10)
	var out atomic.Int64
	var mu sync.Mutex
	var fw *Forwarder
	fw = NewForwarder(ForwarderConfig{Ratio: 2, Burst: 100, Window: time.Hour},
		func(context.Context) (*Client, error) {
			c1, c2 := net.Pipe()
			s := NewServer(c2, Config{}, dialUDP(to))
			t.Cleanup(func() { _ = s.Close() })
			return NewClient(c1, Config{}), nil
		},
		func(p []byte, _ netip.AddrPort) { out.Add(int64(len(p))) })
	defer fw.Close()
	mu.Lock()
	for port := range 5 {
		fw.Handle(context.Background(), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(1000+port)), make([]byte, 100))
	}
	mu.Unlock()
	waitFor(t, "budget drops", func() bool { return fw.Stats().Budget > 0 })
	time.Sleep(100 * time.Millisecond)
	if o := out.Load(); o > 2*500+100 {
		t.Fatalf("wrote %d bytes to a source that sent 500", o)
	}
}

// AllFlowsEnd: idle flows end at both sides, and the client's
// association after AssocIdle with none.
func TestDatagramAssocAllFlowsEnd(t *testing.T) {
	to, _ := echo(t, 1)
	c, s := pair(t, Config{Idle: 50 * time.Millisecond, AssocIdle: 300 * time.Millisecond}, Config{Idle: time.Hour}, dialUDP(to))
	var closed []chan Reason
	for range 5 {
		f, in, cl := recvFlow(c)
		f.Send([]byte("q"))
		recv(t, in)
		closed = append(closed, cl)
	}
	for _, cl := range closed {
		if r := <-cl; r != ReasonIdle {
			t.Fatalf("closed %v", r)
		}
	}
	waitFor(t, "the agent's flows to end", func() bool { return s.Stats().Live == 0 })
	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the idle association did not end")
	}
	if !errors.Is(c.Err(), ErrIdle) {
		t.Fatal(c.Err())
	}
	// The agent's backstop alone.
	c2, s2 := pair(t, Config{Idle: time.Hour}, Config{Idle: 50 * time.Millisecond}, dialUDP(to))
	f, _, cl := recvFlow(c2)
	f.Send([]byte("q"))
	if r := <-cl; r != ReasonBackstop {
		t.Fatalf("closed %v", r)
	}
	waitFor(t, "backstop", func() bool { return s2.Stats().Live == 0 })
}

// NoDeliverAfterRevoke: once the agent ends the association (a
// revocation), nothing more reaches the target and the client's flows end.
func TestDatagramAssocNoDeliverAfterRevoke(t *testing.T) {
	to, got := echo(t, 0)
	c, s := pair(t, Config{}, Config{}, dialUDP(to))
	f, _, cl := recvFlow(c)
	f.Send([]byte("a"))
	waitFor(t, "first datagram", func() bool { return got.Load() == 1 })
	_ = s.Close()
	for range 100 {
		f.Send([]byte("after"))
	}
	<-cl
	time.Sleep(50 * time.Millisecond)
	if got.Load() != 1 {
		t.Fatalf("target got %d after the revocation", got.Load()-1)
	}
}

// 10,000 DNS-style flows (a new source port per query) on one
// association, one open: each a query, its answer, its close.
func TestDatagramAssocDNSFlows(t *testing.T) {
	to, got := echo(t, 1)
	var dials atomic.Int32
	c, s := pair(t, Config{}, Config{}, func() (net.Conn, error) { dials.Add(1); return net.DialUDP("udp", nil, to) })
	const flows, par = 10000, 64
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := range flows {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			ans := make(chan []byte, 1)
			var f *Flow
			var err error
			for {
				if f, err = c.Open(FlowOptions{Deliver: func(p []byte) { ans <- append([]byte(nil), p...) }}); err == nil {
					break
				}
				time.Sleep(time.Millisecond) // closes not yet answered: the table is the client's
			}
			defer f.Close()
			q := fmt.Appendf(nil, "query %d", i)
			f.Send(q)
			select {
			case p := <-ans:
				if !bytes.Equal(p, q) {
					bad.Add(1)
				}
			case <-time.After(10 * time.Second):
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 || got.Load() != flows || dials.Load() != flows {
		t.Fatalf("bad %d, target got %d, sockets %d", bad.Load(), got.Load(), dials.Load())
	}
	if st := c.Stats(); st.Flows != flows || st.QueueFull != 0 {
		t.Fatalf("client %+v", st)
	}
	waitFor(t, "every agent flow closed", func() bool { return s.Stats().Live == 0 })
}

// DatagramConn's net.Conn half, as nettest checks a net.Conn: a client
// flow's Conn against the agent's in-process target.
func TestDatagramConnIsANetConn(t *testing.T) {
	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
		targets := make(chan net.Conn, 1)
		// Datagrams, not a stream: nettest's tests write without pause and
		// then need one marker through, which a full queue drops. Queues
		// above what its 100 ms spins write keep the marker.
		const q = 1 << 18
		cfg := Config{QueueLen: q, QueueBytes: 1 << 30}
		cs1, cs2 := net.Pipe()
		s := NewServer(cs2, cfg, func() (net.Conn, error) {
			a, b := Pipe(q, addr("agent"), addr("target"))
			targets <- b
			return a, nil
		})
		cl := NewClient(cs1, cfg)
		c, err := cl.Dial(addr("c"), addr("svc"))
		if err != nil {
			return nil, nil, nil, err
		}
		// The agent learns of the flow at its first datagram.
		_, _ = c.Write([]byte("hello"))
		t2 := <-targets
		buf := make([]byte, 8)
		if n, err := t2.Read(buf); err != nil || string(buf[:n]) != "hello" {
			return nil, nil, nil, fmt.Errorf("hello: %q %v", buf[:n], err)
		}
		return c, t2, func() { _ = c.Close(); _ = t2.Close(); _ = cl.Close(); _ = s.Close() }, nil
	})
}

func FuzzReadFrame(f *testing.F) {
	for _, fr := range []frame{{typ: frameOpen, id: 1, payload: []byte("q")}, {typ: frameAccept, id: 3}, {typ: frameRefuse, id: 2, reason: ReasonFull},
		{typ: frameData, id: 300, payload: make([]byte, 1300)}, {typ: frameClose, id: 1, reason: ReasonIdle}} {
		f.Add(appendFrame(nil, fr))
	}
	f.Add([]byte{'D', 1, 0xff, 0xff, 0x04})
	f.Fuzz(func(t *testing.T, b []byte) {
		buf := make([]byte, MaxDatagram)
		r := bufio.NewReader(bytes.NewReader(b))
		for {
			fr, err := readFrame(r, buf)
			if err != nil {
				return
			}
			if fr.id == 0 || len(fr.payload) > MaxDatagram {
				t.Fatalf("accepted %+v", fr)
			}
			again, err := readFrame(bufio.NewReader(bytes.NewReader(appendFrame(nil, fr))), make([]byte, MaxDatagram))
			if err != nil || again.typ != fr.typ || again.id != fr.id || again.reason != fr.reason || !bytes.Equal(again.payload, fr.payload) {
				t.Fatalf("round trip of %+v: %+v %v", fr, again, err)
			}
		}
	})
}

// TestDatagramAssocTrace is the run scripts/spec.sh traces records
// (-tags relaytrace) and checks against spec/TraceDatagramAssoc.tla: a
// listener with two admitted sources and one refused, replies, the
// agent's flow cap refusing a third source, and a flow's idle close.
func TestDatagramAssocTrace(t *testing.T) {
	to, _ := echo(t, 2)
	var mu sync.Mutex
	got := map[netip.AddrPort]int{}
	var srv *Server
	fw := NewForwarder(ForwarderConfig{Allow: netip.MustParsePrefix("127.0.0.0/8").Contains},
		func(context.Context) (*Client, error) {
			c1, c2 := net.Pipe()
			srv = NewServer(c2, Config{MaxFlows: 2, Idle: time.Hour}, dialUDP(to))
			return NewClient(c1, Config{MaxFlows: 3, Idle: 200 * time.Millisecond}), nil
		},
		func(p []byte, to netip.AddrPort) { mu.Lock(); got[to]++; mu.Unlock() })
	defer func() { _ = fw.Close(); <-srv.Done() }()
	a, b, c := netip.MustParseAddrPort("127.0.0.1:1001"), netip.MustParseAddrPort("127.0.0.1:1002"), netip.MustParseAddrPort("127.0.0.1:1003")
	ctx := context.Background()
	replies := func(s netip.AddrPort) int { mu.Lock(); defer mu.Unlock(); return got[s] }
	fw.Handle(ctx, a, []byte("a1"))
	waitFor(t, "a's replies", func() bool { return replies(a) == 2 })
	fw.Handle(ctx, netip.MustParseAddrPort("192.0.2.9:53"), []byte("spoofed"))
	fw.Handle(ctx, b, []byte("b1"))
	fw.Handle(ctx, a, []byte("a2"))
	waitFor(t, "replies", func() bool { return replies(a) == 4 && replies(b) == 2 })
	fw.Handle(ctx, c, []byte("c1")) // past the agent's cap: refused
	waitFor(t, "the refusal", func() bool { return srv.Stats().Refused == 1 })
	waitFor(t, "idle closes", func() bool { return srv.Stats().Live == 0 })
	if replies(c) != 0 {
		t.Fatal("a refused flow got a reply")
	}
}
