// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// drainCount is a peerlink.Link that counts its drains.
type drainCount struct {
	peerlink.Link
	drains atomic.Int32
}

func (d *drainCount) Drain(context.Context) error { d.drains.Add(1); return nil }

// A primary's end parks its link for the next primary, which adopts it
// when the relay resumed it (the same bind token); another token, a second
// park, or the agent's stop drains it, and nothing is drained twice.
func TestLinkParkResumeOrDrain(t *testing.T) {
	ctx, stop := context.WithCancel(t.Context())
	p := newLinkPark(ctx)
	a, b := &drainCount{}, &drainCount{}
	p.park(parkedLink{token: "t1", node: a, acc: &linkAccept{}})
	if got := p.parked(); got != "t1" {
		t.Fatalf("parked %q, want t1", got)
	}
	p.park(parkedLink{token: "t2", node: b, acc: &linkAccept{}})
	if a.drains.Load() != 1 {
		t.Fatal("a link parked over another must drain the older")
	}
	z := &lazyLink{ctx: t.Context(), ls: &linkSessions{}}
	z.adopt(p.take())
	if z.node != b || z.token != "t2" || b.drains.Load() != 0 || p.parked() != "" {
		t.Fatalf("adopt: node %v token %q drains %d parked %q", z.node, z.token, b.drains.Load(), p.parked())
	}
	c := &drainCount{}
	p.park(parkedLink{token: "t3", node: c, acc: &linkAccept{}})
	stop()
	for deadline := time.Now().Add(5 * time.Second); c.drains.Load() == 0 && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
	} // context.AfterFunc runs in a goroutine of its own
	if c.drains.Load() != 1 {
		t.Fatal("the agent's stop must drain the parked link")
	}
	d := &drainCount{}
	p.park(parkedLink{token: "t4", node: d, acc: &linkAccept{}})
	if d.drains.Load() != 1 || p.parked() != "" {
		t.Fatal("a link parked after the agent stopped must drain at once")
	}
}

// A link that outlives its primary (parked, then resumed) serves the opens
// that come once the primary ended: its sessions dial their targets in the
// agent's context, not the primary's. An open in flight when the primary
// ended was refused (nfltr-relay's TestAgentLinkSurvivesReconnect).
func TestLinkSessionsDialPastThePrimary(t *testing.T) {
	primary, end := context.WithCancel(t.Context())
	ls := newLinkSessions(newLinkPark(t.Context()), primary, sessionTargets{forwardAddr: echoTarget(t)}, nil, slog.New(slog.DiscardHandler), &tcpStreamGrowth{})
	end()
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go ls.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("open after the primary ended: answer %v, %v; want accepted", a, err)
	}
}
