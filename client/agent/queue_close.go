// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/link/peerlink"
)

// Lane DIRECTCLOSE, PIPEMATRIX defect 1: an accepted session's Close
// returned at once, its program exited 0, and the agent's stop reset the
// direct session once its drain passed with the tail still
// unacknowledged (nfltr-pipe listen exited 0, dial read a short stream
// and exited 6). On a direct path Accept's conn's Close now returns once
// the peer acknowledged every byte and the end, or an error
// (spec/AgentStop.tla CloseTruth, mutant close-returns-early).

// closeSync is the delivery of Accept's conn's end. The session's
// goroutine decides whether one is reported: joinTarget on a direct path
// before Join uses the agent's end (reports), the agent's end's first
// use or end otherwise; then joinTarget reports once the end was
// acknowledged (nil) or could not be (an error).
type closeSync struct {
	decideOnce sync.Once
	decided    chan struct{}
	reports    bool
	once       sync.Once
	done       chan struct{}
	err        error
}

func newCloseSync() *closeSync {
	return &closeSync{decided: make(chan struct{}), done: make(chan struct{})}
}

func (s *closeSync) decide(reports bool) {
	s.decideOnce.Do(func() { s.reports = reports; close(s.decided) })
}

func (s *closeSync) report(err error) {
	s.once.Do(func() { s.err = err; close(s.done) })
}

// wait returns the report; nil at once when none comes (a session
// that reports nothing: a gRPC stream's, a bare pipe). Undecided, it
// waits at most e2eeHeaderTimeout: the session's goroutine joins or drops
// the agent's end within its handshake bound. A report not given within
// psCloseBound (a live peer that takes no bytes) is errUnacked.
func (s *closeSync) wait() error {
	select {
	case <-s.decided:
	case <-time.After(e2eeHeaderTimeout):
		return nil
	}
	if !s.reports {
		return nil
	}
	select {
	case <-s.done:
		return s.err
	case <-time.After(psCloseBound):
		return errUnacked
	}
}

// acker is a session that tells when its peer acknowledged its bytes:
// a direct path's psConn (pathswitch: within its Linger of silence), a
// relayed agent-link session (syncAcker).
type acker interface {
	Written() uint64
	WaitAcked(n uint64, d time.Duration) bool
}

// ackerOf is c's acker, nil when c is none.
func ackerOf(c net.Conn) acker {
	switch v := c.(type) {
	case acker:
		return v
	case syncer:
		return syncAcker{v}
	}
	return nil
}

// syncer is a link session (an agent link's, relayed): Sync returns once
// the relay's Mux read every frame buffered before it.
type syncer interface{ Sync() error }

// syncAcker acknowledges a relayed session's bytes once the relay read
// them (lane RELAYCLOSE, link spec/RelayedClose.tla CloseTruth): the
// relay then delivers its tail and end whatever the agent does next
// (link: a FIN then a failure reads io.EOF). The link's liveness bounds
// Sync; d bounds a relay that is alive but takes nothing.
type syncAcker struct{ s syncer }

func (syncAcker) Written() uint64 { return 0 }

func (a syncAcker) WaitAcked(_ uint64, d time.Duration) bool {
	done := make(chan error, 1)
	go func() { done <- a.s.Sync() }()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(d):
		return false
	}
}

var errUnacked = errors.New("the peer did not acknowledge the session's end")

// joinTarget is peerlink.Join(tc, target), where a acknowledges what
// passed through tc (nil: none does, a plain Join): once the target's
// end reached tc (Join's CloseWrite on it: TLS close_notify) it waits
// until the peer acknowledged every byte, then reports to the target's
// Accept conn (closeSync); unacknowledged, it resets the session.
//
// Where tc is the relayed agent-link session itself (peerlink.SyncsEnd),
// Join's CloseWriteSync onto it is the acknowledgement: Join tells the
// agent's end (QueueConn.EndDelivered), and tc stays a *link.Session
// for Join (Pump, no goroutine while idle).
func joinTarget(tc peerlink.Session, a acker, target net.Conn) error {
	q := queueOf(target)
	switch {
	case q == nil:
	case peerlink.SyncsEnd(tc):
		q.cs.decide(true)
	case a != nil:
		q.cs.decide(true)
		return peerlink.Join(ackedEnd{tc, a, q.cs}, target) // the target's end reports what CloseWrite did not
	}
	return peerlink.Join(tc, target)
}

func queueOf(c net.Conn) *QueueConn {
	switch v := c.(type) {
	case *QueueConn:
		return v
	case *anonTarget:
		return v.QueueConn
	}
	return nil
}

// ackedEnd is tc whose CloseWrite returns once the peer acknowledged
// every byte before it, and reports that to the target's Accept conn.
type ackedEnd struct {
	peerlink.Session
	a  acker
	cs *closeSync
}

func (c ackedEnd) CloseWrite() error {
	err := c.Session.CloseWrite()
	if err == nil && !c.a.WaitAcked(c.a.Written(), psCloseBound) {
		err = errUnacked
	}
	if err != nil {
		_ = c.Session.Reset()
		c.cs.report(link.ErrReset)
		return err
	}
	c.cs.report(nil)
	return nil
}
