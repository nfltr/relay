// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/link"
)

// Stats is a snapshot of an agent's counters (Agent.Stats), for a metrics
// collector to read at scrape time: atomics and link's own counters, read
// when called. Nothing counts between reads and nothing is counted per
// frame. Gauges say "now"; every other field only grows over the agent's
// life.
type Stats struct {
	// The transports the agent's sessions ride: the agent link over
	// link/TLS/TCP (TCP) or QUIC, data connections (DataConn), and the
	// gRPC streams (GRPC).
	TCP, QUIC, DataConn, GRPC TransportStats
	// Reconnects counts the agent's new relay connections by why the one
	// before ended.
	Reconnects Reconnects
	// Fallbacks counts agent links that did not connect the way first
	// tried.
	Fallbacks Fallbacks
}

// TransportStats is one transport's part of Stats.
//
// Conns is a gauge: for TCP and QUIC the agent-link connections up, for
// DataConn the data connections open, for GRPC the relay connections the
// relay accepted (Agent.Connected).
//
// ConnStats is what the transport counts: all of it for QUIC
// (quiclink.Node.Stats) and DataConn (link.Conn.Stats); for TCP the
// sessions, aborts and credit waits (link.Observer: peerlink keeps no
// byte counters); for GRPC the credit waits of streams whose relay
// announced a window (link.Credit). Bytes a transport does not count stay
// zero.
type TransportStats struct {
	Conns int64
	link.ConnStats
}

// Reconnects counts the agent's reconnects by why the previous relay
// connection ended.
type Reconnects struct {
	Move      uint64 // make before break: the relay asked the agent to move, or let a connection go that could move
	Drain     uint64 // the relay let the connection go (a graceful stop, a clean end)
	Lost      uint64 // the connection broke
	DialError uint64 // a redial failed (each attempt)
}

// Fallbacks counts agent links that went another way than first tried.
type Fallbacks struct {
	QUICToTCP  uint64 // QUIC was wanted, TCP bound the link
	LinkToGRPC uint64 // no agent link connected: sessions stayed on the gRPC streams
}

// Transports named to WithLinkObserver.
const (
	ObserveTCP      = "tcp"      // the agent link over link/TLS/TCP
	ObserveDataConn = "dataconn" // data connections
	ObserveGRPC     = "grpc"     // credit waits on the gRPC streams
)

// WithLinkObserver gives the agent's link connections a link.Observer
// each: every event of the agent link over TCP (ObserveTCP), of data
// connections (ObserveDataConn), and the credit waits of the gRPC streams
// (ObserveGRPC); QUIC has no Observer (Stats has its counters). fn is
// called once per connection or stream, never per event; the Observer's
// methods run on the connection's goroutines and must not block (PingRTT
// for a histogram, say).
func WithLinkObserver(fn func(transport string) link.Observer) Option {
	return func(a *agent) { a.stats.observe = fn }
}

// stats is an agent's counters (Stats). A nil *stats counts nothing, so
// paths without an agent (RunTCPTunnel) need no check.
type stats struct {
	tcp, quic, dataConn, grpc transportCounters

	move, drain, lost, dialError atomic.Uint64
	quicToTCP, linkToGRPC        atomic.Uint64

	observe func(transport string) link.Observer // WithLinkObserver; nil: none
}

// transportCounters is one transport's counters: events counted here,
// plus the link.ConnStats of sources (connections, Nodes) while they live
// and their last reading once they ended, so no counter goes back.
type transportCounters struct {
	conns                         atomic.Int64
	opened, aborted, waits, waitN atomic.Uint64

	mu    sync.Mutex
	live  map[*func() link.ConnStats]struct{}
	ended link.ConnStats
}

// observer is the Observer for one connection or stream of transport t:
// it counts into tc when count is set (transports without a ConnStats
// source) and forwards every event to the caller's Observer.
func (s *stats) observer(transport string, tc *transportCounters, g *tcpStreamGrowth, count bool) link.Observer {
	o := &statsObserver{next: link.NopObserver{}, g: g}
	if s != nil {
		if count {
			o.tc = tc
		}
		if s.observe != nil {
			if n := s.observe(transport); n != nil {
				o.next = n
			}
		}
	}
	return o
}

// track counts src's ConnStats into tc while it lives; the returned func
// ends it, keeping its last reading. Conns is the caller's to count.
func (tc *transportCounters) track(src func() link.ConnStats) (untrack func()) {
	if tc == nil {
		return func() {}
	}
	tc.mu.Lock()
	if tc.live == nil {
		tc.live = map[*func() link.ConnStats]struct{}{}
	}
	tc.live[&src] = struct{}{}
	tc.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			last := src()
			tc.mu.Lock()
			delete(tc.live, &src)
			addConnStats(&tc.ended, last)
			tc.ended.QueuedBytes -= last.QueuedBytes // a gauge: nothing queued once ended
			tc.mu.Unlock()
		})
	}
}

func (tc *transportCounters) snapshot() TransportStats {
	ts := TransportStats{Conns: tc.conns.Load()}
	ts.SessionsOpened = tc.opened.Load()
	ts.SessionsAborted = tc.aborted.Load()
	ts.CreditWaits = tc.waits.Load()
	ts.CreditWait = time.Duration(tc.waitN.Load())
	tc.mu.Lock()
	addConnStats(&ts.ConnStats, tc.ended)
	for src := range tc.live {
		addConnStats(&ts.ConnStats, (*src)())
	}
	tc.mu.Unlock()
	return ts
}

func addConnStats(to *link.ConnStats, s link.ConnStats) {
	to.BytesIn += s.BytesIn
	to.BytesOut += s.BytesOut
	to.SessionsOpened += s.SessionsOpened
	to.SessionsAborted += s.SessionsAborted
	to.CreditWaits += s.CreditWaits
	to.CreditWait += s.CreditWait
	to.QueuedBytes += s.QueuedBytes
}

func (s *stats) snapshot(grpcConns int64) Stats {
	if s == nil {
		return Stats{}
	}
	st := Stats{
		TCP: s.tcp.snapshot(), QUIC: s.quic.snapshot(), DataConn: s.dataConn.snapshot(), GRPC: s.grpc.snapshot(),
		Reconnects: Reconnects{Move: s.move.Load(), Drain: s.drain.Load(), Lost: s.lost.Load(), DialError: s.dialError.Load()},
		Fallbacks:  Fallbacks{QUICToTCP: s.quicToTCP.Load(), LinkToGRPC: s.linkToGRPC.Load()},
	}
	st.GRPC.Conns = grpcConns
	return st
}

// Field getters that are nil-safe, for call sites that may have no agent.
func (s *stats) tcpC() *transportCounters {
	if s == nil {
		return nil
	}
	return &s.tcp
}

func (s *stats) quicC() *transportCounters {
	if s == nil {
		return nil
	}
	return &s.quic
}

func (s *stats) dataConnC() *transportCounters {
	if s == nil {
		return nil
	}
	return &s.dataConn
}

func (s *stats) grpcC() *transportCounters {
	if s == nil {
		return nil
	}
	return &s.grpc
}

// conn moves tc's Conns gauge by n.
func (tc *transportCounters) conn(n int64) {
	if tc != nil {
		tc.conns.Add(n)
	}
}

// st is the agent's stats g counts into; nil for none.
func (g *tcpStreamGrowth) st() *stats {
	if g == nil {
		return nil
	}
	return g.stats
}

// statsObserver counts a connection's events (tc, when set), its bound
// connections for linkUp (g, when set) and forwards every event to next.
// Atomics only: no allocation per event (TestStatsObserverAllocs).
type statsObserver struct {
	link.NopObserver
	next link.Observer
	tc   *transportCounters
	g    *tcpStreamGrowth
}

func (o *statsObserver) ConnUp(id link.Identity) {
	o.g.linkConn(1)
	if o.tc != nil {
		o.tc.conns.Add(1)
	}
	o.next.ConnUp(id)
}

func (o *statsObserver) ConnDown(id link.Identity, err error) {
	o.g.linkConn(-1)
	if o.tc != nil {
		o.tc.conns.Add(-1)
	}
	o.next.ConnDown(id, err)
}

func (o *statsObserver) SessionOpen() {
	if o.tc != nil {
		o.tc.opened.Add(1)
	}
	o.next.SessionOpen()
}

func (o *statsObserver) SessionClose(err error) { o.next.SessionClose(err) }

func (o *statsObserver) CreditWait(d time.Duration) {
	if o.tc != nil {
		o.tc.waits.Add(1)
		o.tc.waitN.Add(uint64(d))
	}
	o.next.CreditWait(d)
}

func (o *statsObserver) PingRTT(d time.Duration) { o.next.PingRTT(d) }
func (o *statsObserver) GoAway(id link.Identity) { o.next.GoAway(id) }
func (o *statsObserver) Hop(e link.HopEvent)     { o.next.Hop(e) }
func (o *statsObserver) SessionAbort(a link.Abort, byPeer bool) {
	if o.tc != nil {
		o.tc.aborted.Add(1)
	}
	o.next.SessionAbort(a, byPeer)
}
