// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Config are one side's bounds and timers; zero values are the defaults
// (nfltr docs/decisions/nf1-udp-2026-11-14.md, owner decision 4).
type Config struct {
	// MaxFlows bounds this side's live flows of the association (256).
	// The client's and the agent's are set independently: an open past
	// the agent's is refused (R), the datagram dropped.
	MaxFlows int
	// QueueLen and QueueBytes bound each flow's datagrams queued at this
	// side's sender (64, 256 KiB); past either, a datagram is dropped.
	QueueLen, QueueBytes int
	// Idle closes a flow quiet this long: at the client its idle timer
	// (udp_idle, 60 s: no datagram either way), at the agent its backstop
	// (idle_backstop, 120 s: none from the client).
	Idle time.Duration
	// AssocIdle ends a client's association after this long with no flow
	// (assoc_idle, 5 min); negative: never. The agent ignores it.
	AssocIdle time.Duration
	// MaxDatagram bounds a datagram (max_datagram, 65535); a larger one
	// is dropped (TooLarge).
	MaxDatagram int
}

func (c Config) withDefaults(client bool) Config {
	if c.MaxFlows <= 0 {
		c.MaxFlows = 256
	}
	if c.QueueLen <= 0 {
		c.QueueLen = 64
	}
	if c.QueueBytes <= 0 {
		c.QueueBytes = 256 << 10
	}
	if c.Idle <= 0 {
		c.Idle = 60 * time.Second
		if !client {
			c.Idle = 120 * time.Second
		}
	}
	if c.AssocIdle == 0 {
		c.AssocIdle = 5 * time.Minute
	}
	if c.MaxDatagram <= 0 || c.MaxDatagram > MaxDatagram {
		c.MaxDatagram = MaxDatagram
	}
	return c
}

// Drops counts datagrams dropped, by reason (the sidecar's metric's
// reasons; source_refused and budget are a Forwarder's).
type Drops struct {
	SourceRefused, FlowsFull, QueueFull, TooLarge, Budget, TargetFull, Closed uint64
}

// Stats are an association's counters.
type Stats struct {
	Drops
	Flows     uint64 // flows opened (client) or accepted (agent)
	Refused   uint64 // flows refused (R)
	Live      int    // flows open now
	Datagrams [2]uint64
}

type counters struct {
	sourceRefused, flowsFull, queueFull, tooLarge, budget, targetFull, closed atomic.Uint64
	flows, refused                                                           atomic.Uint64
	in, out                                                                  atomic.Uint64
}

func (c *counters) drops() Drops {
	return Drops{c.sourceRefused.Load(), c.flowsFull.Load(), c.queueFull.Load(), c.tooLarge.Load(), c.budget.Load(), c.targetFull.Load(), c.closed.Load()}
}

const (
	stNew     = iota // opened here, no datagram sent yet (client)
	stOpening        // its O sent, no answer yet (client)
	stOpen
	stClosed
)

// flow is one flow at one side.
type flow struct {
	id                  uint64
	state               int // under assoc.mu
	queued, queuedBytes int // under assoc.mu: in assoc.out
	last                atomic.Int64
	src                 string // the trace's source label (client)
	deliver             func([]byte)
	closedFn            func(Reason)
	conn                net.Conn    // the agent's socket to the target
	in                  chan []byte // the agent's datagrams to it
}

func (f *flow) touch() { f.last.Store(time.Now().UnixNano()) }

type outFrame struct {
	f  frame
	fl *flow // a datagram's flow (its queue counters); nil for control
}

// assoc is one side of an association: its stream, its one sender (the
// FIFO of frames in stream order: control and each flow's datagrams under
// the flow's bounds), its reader (which never waits) and its flows.
type assoc struct {
	cfg    Config
	client bool
	stream io.ReadWriteCloser
	cnt    counters

	mu      sync.Mutex
	out     []outFrame
	flows   map[uint64]*flow
	fresh   map[*flow]struct{} // the client's flows not yet opened (no id)
	high    uint64 // the client's last id; the agent's highest seen
	idleAt  time.Time
	err     error
	wake    chan struct{}
	done    chan struct{}
	endOnce sync.Once
}

func newAssoc(stream io.ReadWriteCloser, cfg Config, client bool) *assoc {
	return &assoc{cfg: cfg.withDefaults(client), client: client, stream: stream, flows: map[uint64]*flow{}, fresh: map[*flow]struct{}{},
		wake: make(chan struct{}, 1), done: make(chan struct{}), idleAt: time.Now()}
}

// enqueue puts f on the stream's FIFO (a.mu held); a datagram of fl only
// within fl's bounds: false when dropped.
func (a *assoc) enqueue(f frame, fl *flow) bool {
	if a.err != nil {
		return false
	}
	if fl != nil {
		if fl.queued >= a.cfg.QueueLen || fl.queuedBytes+len(f.payload) > a.cfg.QueueBytes {
			a.cnt.queueFull.Add(1)
			return false
		}
		fl.queued++
		fl.queuedBytes += len(f.payload)
		f.payload = append([]byte(nil), f.payload...)
	}
	a.out = append(a.out, outFrame{f, fl})
	select {
	case a.wake <- struct{}{}:
	default:
	}
	return true
}

// flushAt is how many encoded bytes the sender writes at once.
const flushAt = 64 << 10

// send is the association's one sender: the only goroutine that waits on
// the stream (its credit).
func (a *assoc) send() {
	var q []outFrame
	var buf []byte
	for {
		select {
		case <-a.wake:
		case <-a.done:
			return
		}
		a.mu.Lock()
		q, a.out = a.out, q[:0]
		for _, o := range q {
			if o.fl != nil {
				o.fl.queued--
				o.fl.queuedBytes -= len(o.f.payload)
			}
		}
		a.mu.Unlock()
		buf = buf[:0]
		for i, o := range q {
			buf = appendFrame(buf, o.f)
			q[i] = outFrame{}
			if len(buf) >= flushAt || i == len(q)-1 {
				if _, err := a.stream.Write(buf); err != nil {
					a.end(err)
					return
				}
				buf = buf[:0]
			}
		}
	}
}

// read runs the reader: each frame to handle, which never waits; the
// association ends at the stream's end or handle's error.
func (a *assoc) read(handle func(frame) error) {
	br := bufio.NewReaderSize(a.stream, 64<<10)
	buf := make([]byte, MaxDatagram)
	for {
		f, err := readFrame(br, buf)
		if err == nil {
			err = handle(f)
		}
		if err != nil {
			a.end(err)
			return
		}
	}
}

// ErrIdle ends a client's association that had no flow for AssocIdle.
var ErrIdle = errors.New("dgram: association idle")

// sweep closes the flows quiet for Idle and, at the client, the
// association with no flow for AssocIdle.
func (a *assoc) sweep(expire func(*flow)) {
	tick := min(a.cfg.Idle/4, time.Second)
	if a.client && a.cfg.AssocIdle > 0 {
		tick = min(tick, a.cfg.AssocIdle/4)
	}
	t := time.NewTicker(max(tick, time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case now := <-t.C:
			cut := now.Add(-a.cfg.Idle).UnixNano()
			a.mu.Lock()
			var quiet []*flow
			for _, f := range a.flows {
				if f.state != stClosed && f.last.Load() < cut {
					quiet = append(quiet, f)
				}
			}
			idle := a.client && a.cfg.AssocIdle > 0 && len(a.flows)+len(a.fresh) == 0 && now.Sub(a.idleAt) >= a.cfg.AssocIdle
			a.mu.Unlock()
			for _, f := range quiet {
				expire(f)
			}
			if idle {
				a.end(ErrIdle)
				return
			}
		}
	}
}

// remove forgets fl (a.mu held); it was closed.
func (a *assoc) remove(fl *flow) {
	fl.state = stClosed
	delete(a.flows, fl.id)
	if len(a.flows) == 0 {
		a.idleAt = time.Now()
	}
}

// end ends the association once: the stream closed, every flow closed
// (the agent's sockets with them).
func (a *assoc) end(err error) {
	a.endOnce.Do(func() {
		traceEnd()
		a.mu.Lock()
		a.err = err
		var fs []*flow
		for _, f := range a.flows {
			fs = append(fs, f)
			a.remove(f)
			if f.in != nil {
				close(f.in)
			}
		}
		for f := range a.fresh {
			fs = append(fs, f)
			f.state = stClosed
		}
		clear(a.fresh)
		a.out = nil
		a.mu.Unlock()
		close(a.done)
		_ = a.stream.Close()
		for _, f := range fs {
			if f.conn != nil {
				_ = f.conn.Close()
			}
			if f.closedFn != nil {
				f.closedFn(0)
			}
		}
	})
}

func (a *assoc) stats() Stats {
	a.mu.Lock()
	live := len(a.flows)
	a.mu.Unlock()
	return Stats{Drops: a.cnt.drops(), Flows: a.cnt.flows.Load(), Refused: a.cnt.refused.Load(), Live: live,
		Datagrams: [2]uint64{a.cnt.in.Load(), a.cnt.out.Load()}}
}

// Err is why the association ended (nil while it runs, io.EOF at the
// peer's clean end).
func (a *assoc) errNow() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}
