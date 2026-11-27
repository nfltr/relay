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
	// Service, at the agent, is what every association of one service
	// shares: a bound on their flows together and their counters
	// together (Service.Stats). nil: this association's bounds only.
	Service *Service
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
	// Direct counts the datagrams this side sent on the direct path;
	// Spills those that did not fit in a packet there and went on the
	// stream (direct.go).
	Direct, Spills uint64
}

// counters are an association's (or a Forwarder's, a Service's) counts,
// indexed by the c* constants.
type counters [nCounters]atomic.Uint64

const (
	cSourceRefused = iota
	cFlowsFull
	cQueueFull
	cTooLarge
	cBudget
	cTargetFull
	cClosed
	cFlows
	cRefused
	cIn
	cOut
	cDirect
	cSpills
	nCounters
)

func (c *counters) stats(live int) Stats {
	l := func(i int) uint64 { return c[i].Load() }
	return Stats{Drops: Drops{l(cSourceRefused), l(cFlowsFull), l(cQueueFull), l(cTooLarge), l(cBudget), l(cTargetFull), l(cClosed)},
		Flows: l(cFlows), Refused: l(cRefused), Live: live, Datagrams: [2]uint64{l(cIn), l(cOut)}, Direct: l(cDirect), Spills: l(cSpills)}
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
	conn                net.Conn     // the agent's socket to the target
	in                  chan []byte  // the agent's datagrams to it
	inBytes             atomic.Int64 // their bytes, queued or being written (Server.toTarget)
}

func (f *flow) touch() { f.last.Store(time.Now().UnixNano()) }

type outFrame struct {
	f  frame
	fl *flow // a datagram's flow (its queue counters); nil for control
	dg bool  // a datagram that may go direct (its flow open at the agent)
}

// assoc is one side of an association: its stream, its one sender (the
// FIFO of frames in stream order: control and each flow's datagrams under
// the flow's bounds), its reader (which never waits) and its flows.
type assoc struct {
	cfg    Config
	client bool
	stream io.ReadWriteCloser
	cnt    counters
	svc    *Service // cfg.Service: the agent's service's shared bound and counters; nil: none
	direct Direct   // the direct path (direct.go); a.mu

	mu      sync.Mutex
	out     []outFrame
	flows   map[uint64]*flow
	fresh   map[*flow]struct{} // the client's flows not yet opened (no id)
	high    uint64             // the client's last id; the agent's highest seen
	idleAt  time.Time
	err     error
	wake    chan struct{}
	done    chan struct{}
	sent    chan struct{} // closed when the sender returned
	endOnce sync.Once
}

func newAssoc(stream io.ReadWriteCloser, cfg Config, client bool) *assoc {
	a := &assoc{cfg: cfg.withDefaults(client), client: client, stream: stream, flows: map[uint64]*flow{}, fresh: map[*flow]struct{}{},
		wake: make(chan struct{}, 1), done: make(chan struct{}), sent: make(chan struct{}), idleAt: time.Now()}
	if !client {
		a.svc = cfg.Service
	}
	return a
}

// enqueue puts f on the stream's FIFO (a.mu held); a datagram of fl only
// within fl's bounds: false when dropped.
func (a *assoc) enqueue(f frame, fl *flow) bool {
	if a.err != nil {
		return false
	}
	if fl != nil {
		if fl.queued >= a.cfg.QueueLen || fl.queuedBytes+len(f.payload) > a.cfg.QueueBytes {
			a.add(cQueueFull, 1)
			return false
		}
		fl.queued++
		fl.queuedBytes += len(f.payload)
		f.payload = append([]byte(nil), f.payload...)
	}
	dg := f.typ == frameData && (!a.client || fl.state == stOpen)
	a.out = append(a.out, outFrame{f, fl, dg})
	select {
	case a.wake <- struct{}{}:
	default:
	}
	return true
}

// flushAt is how many encoded bytes the sender writes at once.
const flushAt = 64 << 10

// send is the association's one sender: the only goroutine that waits on
// the stream (its credit) and on the direct path's send queue.
func (a *assoc) send() {
	defer close(a.sent)
	var q []outFrame
	var buf, dbuf []byte
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
		d := a.direct
		a.mu.Unlock()
		buf = buf[:0]
		for i, o := range q {
			if !(o.dg && d != nil && a.sendDirect(d, &dbuf, o.f, o.fl)) {
				buf = appendFrame(buf, o.f)
			}
			q[i] = outFrame{}
			if len(buf) >= flushAt || i == len(q)-1 && len(buf) > 0 {
				if _, err := a.stream.Write(buf); err != nil {
					a.endAfterReader(err)
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
				a.endWith(ErrIdle, 0, endCut)
				return
			}
		}
	}
}

// add counts d at counter i, in the service's counters too.
func (a *assoc) add(i int, d uint64) {
	a.cnt[i].Add(d)
	if a.svc != nil {
		a.svc.cnt[i].Add(d)
	}
}

// remove forgets fl (a.mu held); it was closed.
func (a *assoc) remove(fl *flow) {
	fl.state = stClosed
	delete(a.flows, fl.id)
	if a.svc != nil {
		a.svc.live.Add(-1) // each flow is in a.flows once: Server.open took its place
	}
	if len(a.flows) == 0 {
		a.idleAt = time.Now()
	}
}

// end ends the association once: the stream closed, every flow closed
// (the agent's sockets with them).
func (a *assoc) end(err error) { a.endWith(err, 0, endNotice) }

// How an association's side ended (the trace's step: DatagramAssoc
// NoticeC/NoticeA, Cut, Revoke).
const (
	endNotice = iota // it read the stream's end, or its write failed
	endCut           // its own end: the client's Close or idle end, the agent's stop
	endRevoke        // the agent's revocation (Server.Close, CloseWith)
)

// tailGrace bounds how long an end with a reason waits for the stream to
// take its closes.
const tailGrace = time.Second

// endWith is end; why non-zero first tells the peer of each flow open at
// this side why it closed (a C frame each on the stream, after the frames
// the sender already wrote, within tailGrace), its targets already closed.
func (a *assoc) endWith(err error, why Reason, by int) {
	a.endOnce.Do(func() {
		a.mu.Lock()
		traceEndStep(a.client, by)
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
		traceCleanup(a.client, by)
		a.mu.Unlock()
		close(a.done)
		if why != 0 && len(fs) > 0 {
			var tail []byte
			for _, f := range fs {
				if f.id != 0 {
					tail = appendFrame(tail, frame{typ: frameClose, id: f.id, reason: why})
				}
			}
			a.writeTail(tail)
		}
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

// endAfterReader is the sender's end at a write error: a peer that ended
// with a reason closed the stream after its tail of closes (endWith), so
// the reader takes what is still to read first and ends the association
// at the stream's end; end(err) only after tailGrace, when it did not.
// Ending at once lost a revocation's reason to a client that was sending
// (TestDatagramAssocRevokeNamedWhileSending).
func (a *assoc) endAfterReader(err error) {
	t := time.NewTimer(tailGrace)
	defer t.Stop()
	select {
	case <-a.done:
	case <-t.C:
	}
	a.end(err)
}

// writeTail writes b once the sender returned, both within tailGrace (a
// stream with no credit is closed without it).
func (a *assoc) writeTail(b []byte) {
	t := time.NewTimer(tailGrace)
	defer t.Stop()
	select {
	case <-a.sent:
	case <-t.C:
		return
	}
	wrote := make(chan struct{})
	go func() { _, _ = a.stream.Write(b); close(wrote) }()
	select {
	case <-wrote:
	case <-t.C:
	}
}

func (a *assoc) stats() Stats {
	a.mu.Lock()
	live := len(a.flows)
	a.mu.Unlock()
	return a.cnt.stats(live)
}

// Err is why the association ended (nil while it runs, io.EOF at the
// peer's clean end).
func (a *assoc) errNow() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}
