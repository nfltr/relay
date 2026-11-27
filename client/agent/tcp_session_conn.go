// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/relay/client/internal/bytequeue"
	"github.com/nfltr/relay/proto/pb"
)

// sessionConn is an E2EE session's end of the tunnel as a net.Conn, the
// one the agent terminates TLS on: Read takes the relay's bytes straight
// from the session queue and Write sends them as frames. A net.Pipe plus a
// goroutine pumping each direction cost two goroutine wake-ups per request
// and per response on the agent, the process that limits the vhost path.
type sessionConn struct {
	t    *tcpTunnel
	id   string
	q    *bytequeue.Queue
	rest []byte // unread tail of the last slice taken from q

	closed atomic.Bool
	once   sync.Once

	// Read deadline: http.Server sets one in the past to stop its
	// background read once a handler finishes.
	expired  atomic.Bool
	mu       sync.Mutex
	timer    *time.Timer
	deadline uint64 // generation: a stale timer must not expire a newer deadline
}

func newSessionConn(t *tcpTunnel, id string, q *bytequeue.Queue) *sessionConn {
	return &sessionConn{t: t, id: id, q: q}
}

func (c *sessionConn) Read(b []byte) (int, error) {
	if len(c.rest) == 0 {
		data, ok := c.q.PopUnless(&c.expired)
		if !ok {
			if c.expired.Load() {
				return 0, os.ErrDeadlineExceeded
			}
			return 0, io.EOF
		}
		c.rest = data
	}
	n := copy(b, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

// Write sends b to the relay as one frame (a copy: the caller reuses b).
func (c *sessionConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if err := c.t.send(&pb.TCPData{SessionId: c.id, Data: append([]byte(nil), b...)}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close ends the session: the relay gets a close frame, a pending Read
// returns, a pending read-deadline timer stops (it would keep the session
// reachable until it fired).
func (c *sessionConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		c.mu.Lock()
		c.stopTimerLocked()
		c.mu.Unlock()
		c.t.closeSession(c.id, c.q)
		_ = c.t.send(&pb.TCPData{SessionId: c.id, Close: true})
	})
	return nil
}

func (c *sessionConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopTimerLocked()
	switch {
	case c.closed.Load(): // no timer for a closed session
	case t.IsZero():
		c.expired.Store(false)
	case !t.After(time.Now()):
		c.expired.Store(true)
		c.q.Wake()
	default:
		c.expired.Store(false)
		gen := c.deadline
		c.timer = time.AfterFunc(time.Until(t), func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.deadline == gen {
				c.expired.Store(true)
				c.q.Wake()
			}
		})
	}
	return nil
}

// stopTimerLocked retires the current deadline's timer (c.mu held).
func (c *sessionConn) stopTimerLocked() {
	c.deadline++
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}

func (c *sessionConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetWriteDeadline is a no-op: a Write waits only for the stream's send
// queue, and fails once the stream is gone.
func (c *sessionConn) SetWriteDeadline(time.Time) error { return nil }

// pipeAddr matches net.Pipe's address, which the reverse proxy saw before:
// not host:port, so no X-Forwarded-For from the tunnel itself.
type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func (c *sessionConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (c *sessionConn) RemoteAddr() net.Addr { return pipeAddr{} }
