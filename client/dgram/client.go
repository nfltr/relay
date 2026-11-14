// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"errors"
	"fmt"
	"io"
	"net"
)

// ErrFlowsFull: the association holds MaxFlows flows.
var ErrFlowsFull = errors.New("dgram: flow table full")

// Client is the client's side of one association: the flows it opens.
type Client struct{ a *assoc }

// NewClient runs the client's side of an association on stream, the
// association's session (its TLS, when the session has one). The client
// owns stream: Close, the peer's end or an idle AssocIdle close it.
func NewClient(stream io.ReadWriteCloser, cfg Config) *Client {
	c := &Client{a: newAssoc(stream, cfg, true)}
	traceOpen(c.a.cfg.MaxFlows)
	go c.a.send()
	go c.a.read(c.handle)
	go c.a.sweep(func(f *flow) { c.closeFlow(f, ReasonIdle, true) })
	return c
}

// FlowOptions are a flow's receivers; each is called from the
// association's reader and must not wait.
type FlowOptions struct {
	// Deliver takes each datagram of the flow from the agent; p is valid
	// only during the call.
	Deliver func(p []byte)
	// Closed is called once when the flow ends other than by its Close:
	// the agent refused or closed it, it was idle (ReasonIdle), or the
	// association ended (0).
	Closed func(Reason)
	// Source labels the flow (its listener's source address) in traces.
	Source string
}

// Flow is one flow of a Client.
type Flow struct {
	c *Client
	f *flow
}

// Open adds a flow (the next id); its first Send opens it at the agent.
// ErrFlowsFull past MaxFlows, net.ErrClosed once the association ended.
func (c *Client) Open(o FlowOptions) (*Flow, error) {
	a := c.a
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.err != nil:
		return nil, net.ErrClosed
	case len(a.flows)+len(a.fresh) >= a.cfg.MaxFlows:
		a.cnt.flowsFull.Add(1)
		return nil, ErrFlowsFull
	}
	f := &flow{state: stNew, deliver: o.Deliver, closedFn: o.Closed, src: o.Source}
	f.touch()
	a.fresh[f] = struct{}{}
	return &Flow{c, f}, nil
}

// Send sends p on the flow and never waits: a datagram over MaxDatagram,
// past the flow's queue, or on a closed flow is dropped and counted.
// It reports whether p was queued.
func (fl *Flow) Send(p []byte) bool {
	a, f := fl.c.a, fl.f
	if len(p) > a.cfg.MaxDatagram {
		a.cnt.tooLarge.Add(1)
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	typ := byte(frameData)
	id := f.id
	switch f.state {
	case stClosed:
		a.cnt.closed.Add(1)
		return false
	case stNew:
		typ, id = frameOpen, a.high+1
	}
	if !a.enqueue(frame{typ: typ, id: id, payload: p}, f) {
		return false
	}
	if typ == frameOpen {
		// Its id now, so opens reach the agent in id order.
		delete(a.fresh, f)
		a.high++
		f.id, f.state = a.high, stOpening
		a.flows[f.id] = f
		a.cnt.flows.Add(1)
		traceRead(f.src, f.id, "open")
	} else {
		traceRead(f.src, f.id, "d")
	}
	a.cnt.out.Add(1)
	f.touch()
	return true
}

// Close ends the flow: the agent is told (C) when it knew the flow.
func (fl *Flow) Close() error {
	fl.c.closeFlow(fl.f, ReasonClosed, false)
	return nil
}

// closeFlow closes f once, telling the agent when its open was sent;
// notify calls its Closed.
func (c *Client) closeFlow(f *flow, why Reason, notify bool) {
	a := c.a
	a.mu.Lock()
	if f.state == stClosed {
		a.mu.Unlock()
		return
	}
	if f.state == stNew {
		delete(a.fresh, f)
		f.state = stClosed
	} else {
		if a.enqueue(frame{typ: frameClose, id: f.id, reason: why}, nil) {
			traceExpireC(f.id)
		}
		a.remove(f)
	}
	a.mu.Unlock()
	if notify && f.closedFn != nil {
		f.closedFn(why)
	}
}

// handle is the client's reader: the agent's answers, datagrams and
// closes.
func (c *Client) handle(fr frame) error {
	a := c.a
	if fr.typ == frameOpen || fr.id > a.highID() {
		return fmt.Errorf("%w: frame %q for flow %d not opened", ErrProtocol, fr.typ, fr.id)
	}
	a.mu.Lock()
	f := a.flows[fr.id]
	switch fr.typ {
	case frameAccept:
		traceRecvC("accept", fr.id, "")
		if f != nil && f.state == stOpening {
			f.state = stOpen
		}
	case frameRefuse, frameClose:
		kind := "close"
		if fr.typ == frameRefuse {
			kind = "refuse"
			a.cnt.refused.Add(1)
		}
		traceRecvC(kind, fr.id, "")
		if f == nil {
			break
		}
		a.remove(f)
		a.mu.Unlock()
		if f.closedFn != nil {
			f.closedFn(fr.reason)
		}
		return nil
	case frameData:
		if f == nil || f.state != stOpen {
			traceRecvC("d", fr.id, "drop")
			a.cnt.closed.Add(1)
			break
		}
		traceRecvC("d", fr.id, "deliver")
		a.cnt.in.Add(1)
		f.touch()
		a.mu.Unlock()
		if f.deliver != nil {
			f.deliver(fr.payload)
		}
		return nil
	}
	a.mu.Unlock()
	return nil
}

func (a *assoc) highID() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.high
}

// Stats are the association's counters.
func (c *Client) Stats() Stats { return c.a.stats() }

// Done is closed when the association ended; Err says why.
func (c *Client) Done() <-chan struct{} { return c.a.done }

// Err is why the association ended, nil while it runs.
func (c *Client) Err() error { return c.a.errNow() }

// Close ends the association and its flows.
func (c *Client) Close() error {
	c.a.end(net.ErrClosed)
	return nil
}
