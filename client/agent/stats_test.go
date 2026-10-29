// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// eventCounter is a caller's Observer (WithLinkObserver) counting what it
// was forwarded.
type eventCounter struct {
	link.NopObserver
	events atomic.Int64
}

func (e *eventCounter) ConnUp(link.Identity)          { e.events.Add(1) }
func (e *eventCounter) ConnDown(link.Identity, error) { e.events.Add(1) }
func (e *eventCounter) SessionOpen()                  { e.events.Add(1) }
func (e *eventCounter) SessionClose(error)            { e.events.Add(1) }
func (e *eventCounter) CreditWait(time.Duration)      { e.events.Add(1) }
func (e *eventCounter) PingRTT(time.Duration)         { e.events.Add(1) }
func (e *eventCounter) GoAway(link.Identity)          { e.events.Add(1) }
func (e *eventCounter) Hop(link.HopEvent)             { e.events.Add(1) }
func (e *eventCounter) SessionAbort(link.Abort, bool) { e.events.Add(1) }

// TestStatsObserverCountsForwardsAndAllocatesNothing: the Observer the
// agent gives its link connections counts into Stats, forwards every
// event to the caller's Observer, and allocates nothing per event.
func TestStatsObserverCountsForwardsAndAllocatesNothing(t *testing.T) {
	next := &eventCounter{}
	st := &stats{observe: func(tr string) link.Observer {
		if tr != ObserveTCP {
			t.Errorf("transport %q", tr)
		}
		return next
	}}
	g := &tcpStreamGrowth{stats: st}
	o := st.observer(ObserveTCP, st.tcpC(), g, true)
	events := func() {
		o.ConnUp(link.Identity{})
		o.SessionOpen()
		o.CreditWait(time.Millisecond)
		o.PingRTT(time.Millisecond)
		o.SessionAbort(link.Abort{Code: 7}, true)
		o.SessionClose(nil)
		o.GoAway(link.Identity{})
		o.Hop(link.HopEvent{})
		o.ConnDown(link.Identity{}, nil)
	}
	events()
	if next.events.Load() != 9 {
		t.Fatalf("forwarded %d events, want 9", next.events.Load())
	}
	s := st.snapshot(0).TCP
	if s.SessionsOpened != 1 || s.SessionsAborted != 1 || s.CreditWaits != 1 || s.CreditWait != time.Millisecond || s.Conns != 0 {
		t.Fatalf("counted %+v", s)
	}
	if n := testing.AllocsPerRun(100, events); n != 0 {
		t.Fatalf("%v allocations per event round, want 0", n)
	}
	if n := testing.AllocsPerRun(100, func() { _ = st.snapshot(0) }); n != 0 {
		t.Fatalf("Stats: %v allocations, want 0", n)
	}
	var nilStats *stats // no agent (RunTCPTunnel): counts nothing, forwards nowhere
	nilStats.observer(ObserveGRPC, nilStats.grpcC(), nil, true).CreditWait(time.Second)
	nilStats.dataConnC().track(func() link.ConnStats { return link.ConnStats{} })()
}

// TestStatsSourcesNeverGoBack: a source's counters stay in Stats after it
// ended; its queued bytes (a gauge) do not.
func TestStatsSourcesNeverGoBack(t *testing.T) {
	var tc transportCounters
	cs := link.ConnStats{BytesIn: 10, BytesOut: 20, SessionsOpened: 1, QueuedBytes: 5}
	untrack := tc.track(func() link.ConnStats { return cs })
	if got := tc.snapshot(); got.BytesIn != 10 || got.QueuedBytes != 5 {
		t.Fatalf("live %+v", got)
	}
	cs.BytesIn = 15
	untrack()
	untrack()
	got := tc.snapshot()
	if got.BytesIn != 15 || got.BytesOut != 20 || got.SessionsOpened != 1 || got.QueuedBytes != 0 {
		t.Fatalf("ended %+v", got)
	}
}

// tokenAuth is a relay's side of a data connection's bind in a test: any
// token binds.
type tokenAuth struct{}

func (tokenAuth) Hello(context.Context, tls.ConnectionState) (byte, []byte, error) {
	return link.MethodToken, nil, nil
}

func (tokenAuth) Verify(context.Context, tls.ConnectionState, byte, []byte) (link.Identity, error) {
	return link.Identity{}, nil
}

// TestDataConnStats: a data connection counts into Stats.DataConn while
// open and after, and its events reach the caller's Observer.
func TestDataConnStats(t *testing.T) {
	agentSide, relaySide := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := make(chan error, 1)
	go func() {
		c, _, err := link.Server(ctx, relaySide, link.Config{Auth: tokenAuth{}})
		if err == nil {
			_, err = dataplane.Wrap(c).Recv()
			_ = c.Close()
		}
		got <- err
	}()
	next := &eventCounter{}
	st := &stats{observe: func(string) link.Observer { return next }}
	dial := RelayDialer{Data: func(context.Context) (net.Conn, error) { return agentSide, nil }}
	err := serveDataConn(ctx, dial, "token", func(s tcpStream) error {
		if n := st.snapshot(0).DataConn.Conns; n != 1 {
			t.Errorf("conns while open %d", n)
		}
		if err := s.Send(&pb.TCPData{SessionId: fingerprintControlSessionID, TargetAddr: "x:1"}); err != nil {
			return err
		}
		_ = s.(*dataplane.Conn).Flush()
		if err := <-got; err != nil {
			t.Error(err)
		}
		return nil
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	s := st.snapshot(0).DataConn
	if s.Conns != 0 || s.BytesOut == 0 {
		t.Fatalf("after %+v", s)
	}
	if next.events.Load() == 0 {
		t.Fatal("the caller's Observer saw nothing")
	}
}
