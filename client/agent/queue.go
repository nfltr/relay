// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/nfltr/link"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
)

// DefaultBacklog is a SessionQueue's backlog when NewSessionQueue is given
// none.
const DefaultBacklog = 16

// SessionQueue is a tcp service's target in this process (Service.Queue,
// instead of Service.Target): a net.Listener whose Accept returns the
// service's sessions. A session waits in the queue unanswered, its
// client's open held, until Accept takes it: only then is it answered
// open. A session that finds the backlog full, or the queue closed, is
// refused (ERROR_REASON_TARGET_REFUSED: its client's open fails, nfnet
// CodeRefused), so a client never sees its session open and then reset
// because nobody accepted it (TestQueueAnswersAtAccept, mutant
// answer-at-enqueue).
//
// What Accept returns is a *QueueConn joined to the session the way a
// target's connection is (peerlink.Join): its half close, reset,
// organisation TLS and revocation cut as for any target, without a
// loopback port.
type SessionQueue struct {
	backlog int
	mu      sync.Mutex
	pending []*queued
	sig     chan struct{} // closed at each change of pending or closed
	closed  bool
	done    chan struct{}
}

// queued is one session waiting for Accept, with both ends of its pipe:
// Accept closes taken and returns user; the session's goroutine joins
// agentEnd to the session.
type queued struct {
	user, agentEnd *QueueConn
	taken          chan struct{}
}

// ErrBacklogFull refuses a session that found its queue's backlog full.
var ErrBacklogFull = errors.New("the service's backlog is full: no session accepted in time")

// errQueueClosed refuses a session that reached a closed queue.
var errQueueClosed = errors.New("the service is closed")

// NewSessionQueue returns a queue that holds at most backlog sessions
// waiting for Accept (DefaultBacklog when backlog <= 0).
func NewSessionQueue(backlog int) *SessionQueue {
	if backlog <= 0 {
		backlog = DefaultBacklog
	}
	return &SessionQueue{backlog: backlog, sig: make(chan struct{}), done: make(chan struct{})}
}

// Accept waits for the next session, answers it open and returns it: a
// *QueueConn. After Close it returns net.ErrClosed.
func (q *SessionQueue) Accept() (net.Conn, error) {
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return nil, net.ErrClosed
		}
		if len(q.pending) > 0 {
			e := q.pending[0]
			q.pending = q.pending[1:]
			q.mu.Unlock()
			close(e.taken) // the session's goroutine answers the open, then joins agentEnd
			return e.user, nil
		}
		sig := q.sig
		q.mu.Unlock()
		<-sig
	}
}

// Close refuses the sessions waiting and every later one; Accept returns
// net.ErrClosed. The sessions accepted before go on: their QueueConns are
// their owners'.
func (q *SessionQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.done)
		q.changed()
	}
	return nil
}

// Addr is the queue's address: a pipe's, no port.
func (q *SessionQueue) Addr() net.Addr { return pipeAddr{} }

func (q *SessionQueue) changed() {
	close(q.sig)
	q.sig = make(chan struct{})
}

// enter is a session's dial of its queue: it waits until Accept took it
// (the agent's end of its pipe), the queue closed or ctx ended (refused:
// the answer's reason and why). It answers nothing: the caller answers
// the open once enter returned a conn, as after a target's dial.
func (q *SessionQueue) enter(ctx context.Context, caller *pb.CallerIdentity) (net.Conn, relayv1.ErrorReason, error) {
	refused := relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED
	q.mu.Lock()
	switch {
	case q.closed:
		q.mu.Unlock()
		return nil, refused, errQueueClosed
	case len(q.pending) >= q.backlog:
		q.mu.Unlock()
		return nil, refused, ErrBacklogFull
	}
	e := &queued{taken: make(chan struct{})}
	e.user, e.agentEnd = newQueuePipe()
	e.user.caller = Session{caller: caller}
	q.pending = append(q.pending, e)
	q.changed()
	q.mu.Unlock()
	if err := q.wait(ctx, e); err != nil {
		return nil, refused, err
	}
	return e.agentEnd, 0, nil
}

// wait waits until Accept took e (nil), the queue closed or ctx ended.
func (q *SessionQueue) wait(ctx context.Context, e *queued) error {
	select {
	case <-e.taken:
		return nil
	case <-q.done:
	case <-ctx.Done():
	}
	if q.remove(e) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errQueueClosed
	}
	if ctx.Err() != nil { // Accept took it as the tunnel ended
		_ = e.agentEnd.Reset()
		return ctx.Err()
	}
	return nil
}

// remove takes e out of the queue; false: Accept took it.
func (q *SessionQueue) remove(e *queued) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, p := range q.pending {
		if p == e {
			q.pending = append(q.pending[:i], q.pending[i+1:]...)
			q.changed()
			return true
		}
	}
	return false
}

// queuePipeWindow is how many bytes one direction of a QueueConn holds
// unread: a Write past it waits for the reader (backpressure, as a
// session's credit).
const queuePipeWindow = 64 << 10

// QueueConn is a session a SessionQueue accepted: a net.Conn with a half
// close (CloseWrite) and a failed end (Reset), as a peerlink.Session.
// Read returns io.EOF at the client's half close (or clean end), and
// link.ErrReset at a cut (the client's reset, the agent's stop, an
// organisation admission that ended). Deadlines work for both Read and
// Write; a Write past queuePipeWindow unread bytes waits.
type QueueConn struct {
	r, w   *pipeDir // r: bytes to this end; w: bytes from it
	rd, wd pipeDeadline
	once   sync.Once
	done   chan struct{}
	// resetOnClose: the agent's end, whose Close is a reset unless both
	// directions ended (a target's failure paths close it: its owner must
	// not take that for a clean end).
	resetOnClose bool
	caller       Session
}

// pipeDir is one direction of a QueueConn pair.
type pipeDir struct {
	mu      sync.Mutex
	buf     []byte
	eof     bool  // the writer ended (CloseWrite, Close)
	err     error // a reset: the reader's and the writer's error
	rclosed bool  // the reader closed: writes fail io.ErrClosedPipe
	sig     chan struct{}
}

func newPipeDir() *pipeDir { return &pipeDir{sig: make(chan struct{})} }

// changed wakes the waiters (d.mu held).
func (d *pipeDir) changed() {
	close(d.sig)
	d.sig = make(chan struct{})
}

func newQueuePipe() (user, agentEnd *QueueConn) {
	a, b := newPipeDir(), newPipeDir()
	user = &QueueConn{r: a, w: b, rd: makePipeDeadline(), wd: makePipeDeadline(), done: make(chan struct{})}
	agentEnd = &QueueConn{r: b, w: a, rd: makePipeDeadline(), wd: makePipeDeadline(), done: make(chan struct{}), resetOnClose: true}
	return user, agentEnd
}

// Done is closed at this end's Close or Reset.
func (c *QueueConn) Done() <-chan struct{} { return c.done }

// Caller is who opened the session, as the relay authenticated it; ok is
// false when the relay named no caller.
func (c *QueueConn) Caller() (Caller, bool) { return c.caller.Caller() }

func (c *QueueConn) Read(b []byte) (int, error) {
	d := c.r
	for {
		select {
		case <-c.done:
			return 0, net.ErrClosed
		case <-c.rd.wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		d.mu.Lock()
		switch {
		case d.err != nil:
			d.mu.Unlock()
			return 0, d.err
		case len(d.buf) > 0:
			n := copy(b, d.buf)
			d.buf = d.buf[n:]
			if len(d.buf) == 0 {
				d.buf = nil
			}
			d.changed()
			d.mu.Unlock()
			return n, nil
		case d.eof:
			d.mu.Unlock()
			return 0, io.EOF
		}
		sig := d.sig
		d.mu.Unlock()
		select {
		case <-sig:
		case <-c.rd.wait():
		case <-c.done:
		}
	}
}

func (c *QueueConn) Write(b []byte) (int, error) {
	d := c.w
	n := 0
	for {
		select {
		case <-c.done:
			return n, net.ErrClosed
		case <-c.wd.wait():
			return n, os.ErrDeadlineExceeded
		default:
		}
		d.mu.Lock()
		switch {
		case d.err != nil:
			d.mu.Unlock()
			return n, d.err
		case d.rclosed || d.eof:
			d.mu.Unlock()
			return n, io.ErrClosedPipe
		}
		if k := min(queuePipeWindow-len(d.buf), len(b)-n); k > 0 {
			d.buf = append(d.buf, b[n:n+k]...)
			n += k
			d.changed()
		}
		if n == len(b) {
			d.mu.Unlock()
			return n, nil
		}
		sig := d.sig
		d.mu.Unlock()
		select {
		case <-sig:
		case <-c.wd.wait():
		case <-c.done:
		}
	}
}

// CloseWrite ends this end's writes: the peer reads io.EOF after them.
func (c *QueueConn) CloseWrite() error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	if !c.w.eof && c.w.err == nil {
		c.w.eof = true
		c.w.changed()
	}
	return nil
}

// Close ends both directions: the peer reads io.EOF after this end's
// bytes and its writes fail. The agent's end resets instead unless both
// directions had ended.
func (c *QueueConn) Close() error {
	if c.resetOnClose {
		c.r.mu.Lock()
		c.w.mu.Lock()
		clean := c.r.eof && c.w.eof
		c.w.mu.Unlock()
		c.r.mu.Unlock()
		if !clean {
			return c.Reset()
		}
	}
	c.end(nil)
	return nil
}

// Reset ends the session as failed: the peer reads link.ErrReset, its
// unread bytes dropped.
func (c *QueueConn) Reset() error {
	c.end(link.ErrReset)
	return nil
}

func (c *QueueConn) end(reset error) {
	c.once.Do(func() {
		close(c.done)
		c.rd.set(time.Time{})
		c.wd.set(time.Time{})
		for _, d := range []*pipeDir{c.r, c.w} {
			d.mu.Lock()
			switch {
			case reset != nil:
				if d.err == nil {
					d.err, d.buf = reset, nil
				}
			case d == c.w:
				d.eof = true
			default:
				d.rclosed, d.buf = true, nil
			}
			d.changed()
			d.mu.Unlock()
		}
	})
}

func (c *QueueConn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return nil
}
func (c *QueueConn) SetReadDeadline(t time.Time) error  { c.rd.set(t); return nil }
func (c *QueueConn) SetWriteDeadline(t time.Time) error { c.wd.set(t); return nil }
func (c *QueueConn) LocalAddr() net.Addr                { return pipeAddr{} }
func (c *QueueConn) RemoteAddr() net.Addr               { return pipeAddr{} }

// pipeDeadline is net.Pipe's deadline: a channel closed once it passed.
type pipeDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func makePipeDeadline() pipeDeadline { return pipeDeadline{cancel: make(chan struct{})} }

func (d *pipeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired: wait for its close
	}
	d.timer = nil
	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *pipeDeadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
