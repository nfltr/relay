// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"sync/atomic"

	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
	"github.com/nfltr/relay/client/dgram"
)

// sessionDatagrams is a framed session's direct datagrams (dgram.Direct,
// nfltr docs/decisions/nf1-udp-2026-11-14.md "The direct path"): sent on
// the session's current stream when that is a direct one; taken from a
// direct stream only while it is still the session's current stream and
// the session runs (pathswitch Current: nil once reset, so nothing reaches
// a target after a revocation however late the cleanup:
// direct-ignores-assoc), and at the client only once that stream's agent
// token was checked (BIND:dgram.tag: the stream is bound to this session
// by both tokens). The tag that picks the session on its connection is the
// stream's QUIC stream id (quiclink).
type sessionDatagrams struct {
	c    *pathswitch.Conn
	on   atomic.Pointer[func([]byte)]
	recv *atomic.Uint64 // direct bytes received (the client's metrics); nil: none
}

var _ dgram.Direct = (*sessionDatagrams)(nil)

func (d *sessionDatagrams) SendDatagram(p []byte) error {
	st, ok := d.c.Current().(interface{ SendDatagram([]byte) error })
	if !ok {
		return dgram.ErrNotDirect
	}
	return st.SendDatagram(p)
}

func (d *sessionDatagrams) OnDatagram(f func([]byte)) { d.on.Store(&f) }

// take hands the datagrams of s, the session's direct stream cur (as the
// path layer holds it), to the receiver, while cur is the session's
// current stream and bound (nil: no check of its own).
func (d *sessionDatagrams) take(cur pathswitch.Stream, s *quiclink.Session, bound func() bool) {
	s.OnDatagram(func(p []byte) {
		if d.c.Current() != cur || bound != nil && !bound() {
			return // an old stream's, a reset session's, an unproved stream's
		}
		if d.recv != nil {
			d.recv.Add(uint64(len(p)))
		}
		if f := d.on.Load(); f != nil && *f != nil {
			(*f)(p)
		}
	})
}

// SendDatagram sends p as a datagram of the stream when it is a direct
// one (a quiclink session whose connection carries datagrams).
func (s pathStream) SendDatagram(p []byte) error {
	q, ok := s.Conn.(*quiclink.Session)
	if !ok {
		return dgram.ErrNotDirect
	}
	err := q.SendDatagram(p)
	if _, big := errors.AsType[*quic.DatagramTooLargeError](err); err != nil && !big {
		return dgram.ErrNotDirect // no datagrams there, the stream reset, its connection closed: the stream carries it
	}
	if err == nil && s.sent != nil {
		s.sent.Add(uint64(len(p)))
	}
	return err
}
