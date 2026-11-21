// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/quic-go"
)

// dropConn is the agent's socket behind a NAT whose filter is closed while
// drop is set: the client's QUIC packets (long or short header, first bit
// set) never reach it; its own probes still leave.
type dropConn struct {
	c    *net.UDPConn
	drop atomic.Bool
}

func (c *dropConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, a, err := c.c.ReadFrom(p)
		if err != nil || n == 0 || p[0]&0x80 == 0 || !c.drop.Load() {
			return n, a, err
		}
	}
}
func (c *dropConn) WriteTo(p []byte, a net.Addr) (int, error) { return c.c.WriteTo(p, a) }
func (c *dropConn) LocalAddr() net.Addr                       { return c.c.LocalAddr() }
func (c *dropConn) SetDeadline(t time.Time) error             { return c.c.SetDeadline(t) }
func (c *dropConn) SetReadDeadline(t time.Time) error         { return c.c.SetReadDeadline(t) }
func (c *dropConn) SetWriteDeadline(t time.Time) error        { return c.c.SetWriteDeadline(t) }
func (c *dropConn) Close() error                              { return c.c.Close() }

// dropRig is a rig whose agent serves its direct paths on a dropConn, the
// client's attempts bounded by bound and recorded.
func dropRig(t *testing.T, bound time.Duration) (*directRig, *dropConn, func() []punchAttempt) {
	t.Helper()
	r := newDirectRig(t, DirectOn)
	r.d.punchBound = bound
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dc := &dropConn{c: uc}
	table := r.l.targets.services
	old := table.direct
	ep := &DirectEndpoint{pc: dc, tr: &quic.Transport{Conn: dc}, loopback: true}
	d, err := newDirectServerOn(ep, old.org, old.groups, old.modes)
	if err != nil {
		t.Fatal(err)
	}
	table.direct = d
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = d.node.Drain(ctx)
		_ = ep.Close()
	})
	var mu sync.Mutex
	var got []punchAttempt
	r.d.attempted = func(a punchAttempt) {
		mu.Lock()
		got = append(got, a)
		mu.Unlock()
	}
	return r, dc, func() []punchAttempt {
		mu.Lock()
		defer mu.Unlock()
		return append([]punchAttempt(nil), got...)
	}
}

// checkTimed: every attempt that dialled waited half its exchange's round
// trip after its sync, and dialled no sooner (spec/PunchRound.tla
// InitialAfterProbe).
func checkTimed(t *testing.T, as []punchAttempt) {
	t.Helper()
	for _, a := range as {
		if a.rtt <= 0 || a.wait != a.rtt/2 || a.sinceSync < a.wait {
			t.Errorf("attempt %d: rtt %s, wait %s, dialled %s after the sync; want a wait of rtt/2 and no dial before it", a.n, a.rtt, a.wait, a.sinceSync)
		}
	}
}

// TestDirectPunchRetriesAfterNoAnswer: an attempt no candidate answered
// (the agent's NAT dropped every Initial) is followed at once by another,
// with its own exchange; the second goes direct and says so (Attempts 2).
func TestDirectPunchRetriesAfterNoAnswer(t *testing.T) {
	r, dc, attempts := dropRig(t, 500*time.Millisecond)
	dc.drop.Store(true)
	r.d.attempted = func(next func(punchAttempt)) func(punchAttempt) {
		return func(a punchAttempt) {
			next(a)
			if a.n == 1 {
				dc.drop.Store(false) // the NAT opens: the second attempt passes
			}
		}
	}(r.d.attempted)
	_, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() {
		if e := waitPath(t, events, PathDirect); e.Attempts != 2 {
			t.Errorf("direct after %d attempts, want 2", e.Attempts)
		}
	})
	as := attempts()
	if len(as) != 2 || as[0].reason != ReasonNoAnswer || as[1].reason != "" {
		t.Fatalf("attempts %+v, want no_answer then a win", as)
	}
	checkTimed(t, as)
	if st := r.d.Stats(); st.Punches[ReasonNoAnswer] != 1 || st.Punches["ok"] != 1 {
		t.Fatalf("punches %v, want one no_answer, one ok", st.Punches)
	}
}

// TestDirectPunchRoundEndsRelayedAfterThreeAttempts: a pair no punch passes
// is tried three times, then the round ends relayed (Attempts 3), the
// session carrying its bytes relayed all along.
func TestDirectPunchRoundEndsRelayedAfterThreeAttempts(t *testing.T) {
	r, dc, attempts := dropRig(t, 300*time.Millisecond)
	dc.drop.Store(true)
	_, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() {
		if e := waitPath(t, events, PathRelayed); e.Reason != ReasonNoAnswer || e.Attempts != punchAttempts {
			t.Errorf("path event %+v, want relayed, no_answer after %d attempts", e, punchAttempts)
		}
	})
	as := attempts()
	if len(as) != punchAttempts {
		t.Fatalf("%d attempts, want %d", len(as), punchAttempts)
	}
	for i, a := range as {
		if a.n != i+1 || a.reason != ReasonNoAnswer {
			t.Errorf("attempt %d: %+v, want no_answer", i+1, a)
		}
	}
	checkTimed(t, as)
	if st := r.d.Stats(); st.Punches[ReasonNoAnswer] != punchAttempts {
		t.Fatalf("punches %v, want %d no_answer", st.Punches, punchAttempts)
	}
}
