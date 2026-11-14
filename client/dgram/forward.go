// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// ForwarderConfig is a datagram listener's admission and amplification
// budget (nfltr docs/decisions/nf1-udp-2026-11-14.md section 3).
type ForwarderConfig struct {
	// Allow admits a source before any lookup (allow_sources); nil admits
	// every source: a loopback listen only.
	Allow func(netip.Addr) bool
	// Ratio and Burst bound what the listener writes to each source
	// address: at most Ratio times the bytes it received from it, plus
	// Burst, per Window (counted per address, not per flow: a new flow
	// does not reset it). Ratio 0: no budget (a loopback listen).
	Ratio, Burst int
	Window       time.Duration
}

// Forwarder is a datagram listener's client side: one flow per source
// address of one association at a time, opened by Dial when a datagram
// finds none (the reader waits for that open, nothing else). Replies go to
// Write, each to its flow's source.
type Forwarder struct {
	cfg   ForwarderConfig
	fcfg  Config
	dial  func(context.Context) (*Client, error)
	write func(p []byte, to netip.AddrPort)

	mu      sync.Mutex
	c       *Client
	flows   map[netip.AddrPort]*Flow
	budgets map[netip.Addr]*budget
	cnt     counters // its own drops: source refused, budget
}

type budget struct {
	in, out int
	since   time.Time
}

// NewForwarder is a listener's forwarder: dial opens an association (the
// target's session, NewClient on it), write sends a reply to a source and
// must not wait.
func NewForwarder(cfg ForwarderConfig, dial func(context.Context) (*Client, error), write func([]byte, netip.AddrPort)) *Forwarder {
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Second
	}
	return &Forwarder{cfg: cfg, dial: dial, write: write, flows: map[netip.AddrPort]*Flow{}, budgets: map[netip.Addr]*budget{}}
}

// Handle takes one datagram p the listener read from src. It waits only
// for an association's open; every other overflow is a counted drop.
func (fw *Forwarder) Handle(ctx context.Context, src netip.AddrPort, p []byte) {
	addr := src.Addr().Unmap()
	if fw.cfg.Allow != nil && !fw.cfg.Allow(addr) {
		traceReadDrop(src.String(), false)
		fw.cnt.sourceRefused.Add(1)
		return
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.cfg.Ratio > 0 {
		b := fw.budgetOf(addr)
		b.in += len(p)
	}
	fl := fw.flows[src]
	if fl == nil {
		c, err := fw.client(ctx)
		if err != nil {
			traceReadDrop(src.String(), true)
			return
		}
		var mine *Flow
		fl, err = c.Open(FlowOptions{Source: src.String(),
			Deliver: func(p []byte) { fw.reply(src, p) },
			Closed:  func(Reason) { fw.forget(src, &mine) }})
		mine = fl
		if err != nil {
			traceReadDrop(src.String(), true)
			return
		}
		fw.flows[src] = fl
	}
	fl.Send(p)
}

// client is the association, opened when none runs (fw.mu held).
func (fw *Forwarder) client(ctx context.Context) (*Client, error) {
	if fw.c != nil {
		select {
		case <-fw.c.Done():
			fw.c = nil
			clear(fw.flows)
		default:
			return fw.c, nil
		}
	}
	c, err := fw.dial(ctx)
	if err != nil {
		return nil, err
	}
	fw.c = c
	return c, nil
}

// reply writes p to src within src's budget, else drops it.
func (fw *Forwarder) reply(src netip.AddrPort, p []byte) {
	if fw.cfg.Ratio > 0 {
		fw.mu.Lock()
		b := fw.budgetOf(src.Addr().Unmap())
		ok := b.out+len(p) <= fw.cfg.Ratio*b.in+fw.cfg.Burst
		if ok {
			b.out += len(p)
		}
		fw.mu.Unlock()
		if !ok {
			fw.cnt.budget.Add(1)
			return
		}
	}
	fw.write(p, src)
}

// budgetOf is addr's budget of this window (fw.mu held); a window's end
// starts every address's anew.
func (fw *Forwarder) budgetOf(addr netip.Addr) *budget {
	b := fw.budgets[addr]
	if b == nil || time.Since(b.since) >= fw.cfg.Window {
		b = &budget{since: time.Now()}
		if len(fw.budgets) > 4096 {
			clear(fw.budgets) // ponytail: a burst of admitted sources resets budgets early; per-entry expiry if allow lists grow large
		}
		fw.budgets[addr] = b
	}
	return b
}

// forget drops src's flow *fl, once closed (and not a later flow of src).
func (fw *Forwarder) forget(src netip.AddrPort, fl **Flow) {
	fw.mu.Lock()
	if fw.flows[src] == *fl {
		delete(fw.flows, src)
	}
	fw.mu.Unlock()
}

// Stats are the current association's counters plus the forwarder's own
// drops (SourceRefused, Budget).
func (fw *Forwarder) Stats() Stats {
	fw.mu.Lock()
	c := fw.c
	fw.mu.Unlock()
	var s Stats
	if c != nil {
		s = c.Stats()
	}
	s.SourceRefused = fw.cnt.sourceRefused.Load()
	s.Budget = fw.cnt.budget.Load()
	return s
}

// Close ends the association.
func (fw *Forwarder) Close() error {
	fw.mu.Lock()
	c := fw.c
	fw.c = nil
	fw.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}
