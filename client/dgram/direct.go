// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"encoding/binary"
	"errors"
)

// The direct path (nfltr docs/decisions/nf1-udp-2026-11-14.md "The direct
// path"): while the association's session is attached to a direct QUIC
// connection, its datagrams ride QUIC DATAGRAM frames there (lossy,
// unordered, never behind a lost packet) instead of D frames on the
// stream. A frame's payload, under the session's tag, is the flow id
// (uvarint) and the datagram. Control (O, A, R, C) always rides the
// stream. The client sends a flow's datagrams direct once the agent
// accepted the flow (before, they follow its O on the stream); the agent
// sends every reply direct. The carrier sends direct only once the far end
// is bound there (the client once the agent attached, the agent once it
// took a client's frame; relay spec/DatagramAssoc.tla NoLostOnMove), else
// ErrNotDirect and the stream carries it. A datagram that does not fit in a packet
// spills to the stream (counted Spills), never fragmented. A direct frame
// is taken only while the association runs, for a flow open at this side:
// the carrier (Direct) checks the session's state and tag first, so a
// frame never reaches a target after the session's reset (relay
// spec/DatagramAssoc.tla RecvDgA: direct-ignores-assoc). At the client a
// direct reply to a flow still opening is its accept (it can overtake the
// A on the stream: RecvDgC).

// Direct is an association's direct path: its session's datagrams beside
// its stream (agent.DirectSession's, the agent's framed sessions').
type Direct interface {
	// SendDatagram sends p as one datagram on the direct path, or fails:
	// ErrNotDirect (the session is not attached direct now, or its
	// connection carries no datagrams) or another error (p does not fit:
	// the sender spills it to the stream). It may wait (QUIC's send
	// queue): the association's sender calls it, never a reader.
	SendDatagram(p []byte) error
	// OnDatagram sets the receiver of the direct path's datagrams; f must
	// not wait.
	OnDatagram(f func(p []byte))
}

// ErrNotDirect: the session is not on a direct path that carries
// datagrams.
var ErrNotDirect = errors.New("dgram: not on a direct path")

// SetDirect gives the association its direct path (a session that may
// move; nil: relayed only).
func (c *Client) SetDirect(d Direct) { c.a.setDirect(d, c.directIn) }

// SetDirect gives the association its direct path.
func (s *Server) SetDirect(d Direct) { s.a.setDirect(d, s.directIn) }

func (a *assoc) setDirect(d Direct, in func(id uint64, p []byte)) {
	a.mu.Lock()
	a.direct = d
	a.mu.Unlock()
	if d != nil {
		d.OnDatagram(func(b []byte) {
			id, n := binary.Uvarint(b)
			if n <= 0 || id == 0 {
				a.cnt.closed.Add(1) // a malformed frame: lost, as UDP's
				return
			}
			in(id, b[n:])
		})
	}
}

// sendDirect sends a datagram frame direct: false when it goes on the
// stream instead (not direct, or spilled). It is counted Direct before
// the path has it, since its reply may be read before SendDatagram
// returns, and uncounted when the path refuses it (nothing left then):
// TestDatagramAssocDirectCountedBeforeItLeaves.
func (a *assoc) sendDirect(d Direct, buf *[]byte, f frame, fl *flow) bool {
	*buf = binary.AppendUvarint((*buf)[:0], f.id)
	*buf = append(*buf, f.payload...)
	a.cnt.direct.Add(1)
	err := traceSend(d, *buf, a.client, fl.src, f.id)
	if err == nil {
		return true
	}
	a.cnt.direct.Add(^uint64(0))
	if !errors.Is(err, ErrNotDirect) {
		a.cnt.spills.Add(1)
	}
	return false
}

// directIn is the client's direct receiver: a reply of an open flow, or of
// one opening (it opens it).
func (c *Client) directIn(id uint64, p []byte) {
	a := c.a
	a.mu.Lock()
	f := a.flows[id]
	if a.err != nil || f == nil || f.state == stClosed {
		traceRecvDg(true, id, "drop")
		a.mu.Unlock()
		a.cnt.closed.Add(1)
		return
	}
	traceRecvDg(true, id, "deliver")
	f.state = stOpen
	a.cnt.in.Add(1)
	f.touch()
	a.mu.Unlock()
	if f.deliver != nil {
		f.deliver(p)
	}
}

// directIn is the agent's direct receiver: a datagram of an open flow, to
// its target.
func (s *Server) directIn(id uint64, p []byte) {
	a := s.a
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.flows[id]
	if a.err != nil || f == nil || f.state != stOpen {
		traceRecvDg(false, id, "drop")
		a.cnt.closed.Add(1)
		return
	}
	traceRecvDg(false, id, "deliver")
	f.touch()
	select {
	case f.in <- append([]byte(nil), p...):
		a.cnt.in.Add(1)
	default:
		a.cnt.targetFull.Add(1)
	}
}
