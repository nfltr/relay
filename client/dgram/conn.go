// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Conn is one flow as a net.Conn with message semantics: each Write is one
// datagram (it never waits: a datagram the flow cannot take is dropped, as
// UDP drops), each Read one datagram (one larger than the buffer is
// dropped with io.ErrShortBuffer). It is a net.PacketConn too, with one
// peer: WriteTo ignores the address, ReadFrom returns RemoteAddr.
type Conn struct {
	send          func([]byte) bool
	stop          func()
	recv          chan []byte
	local, remote net.Addr
	drops         *counters

	mu       sync.Mutex
	closed   bool
	done     chan struct{} // closed by Close or the flow's end
	rdl      time.Time
	rdlWake  chan struct{} // closed when rdl changes
	wdl      time.Time
	closeErr error
}

func newConn(queue int, local, remote net.Addr, drops *counters) *Conn {
	return &Conn{recv: make(chan []byte, queue), local: local, remote: remote, drops: drops,
		done: make(chan struct{}), rdlWake: make(chan struct{})}
}

// put hands c a datagram from its peer, dropped when c's queue is full
// (never waits).
func (c *Conn) put(p []byte) {
	select {
	case c.recv <- append([]byte(nil), p...):
	default:
		c.drops.queueFull.Add(1)
	}
}

// end ends c from its flow's side (no more datagrams).
func (c *Conn) end() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
}

// Dial opens a flow of the association as a Conn (local, remote: its
// addresses).
func (cl *Client) Dial(local, remote net.Addr) (*Conn, error) {
	var c *Conn
	fl, err := cl.Open(FlowOptions{Deliver: func(p []byte) { c.put(p) }, Closed: func(Reason) { c.end() }})
	if err != nil {
		return nil, err
	}
	c = newConn(cl.a.cfg.QueueLen, local, remote, &cl.a.cnt)
	c.send, c.stop = fl.Send, func() { _ = fl.Close() }
	return c, nil
}

// Pipe is a pair of Conns joined in memory, each Write one Read at the
// other (queue datagrams each way, the rest dropped): a datagram service's
// target in the process (Dial's sockets).
func Pipe(queue int, a, b net.Addr) (*Conn, *Conn) {
	var cnt counters
	x, y := newConn(queue, a, b, &cnt), newConn(queue, b, a, &cnt)
	x.send = func(p []byte) bool { y.put(p); return true }
	y.send = func(p []byte) bool { x.put(p); return true }
	x.stop, y.stop = y.end, x.end
	return x, y
}

func (c *Conn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		dl, wake := c.rdl, c.rdlWake
		c.mu.Unlock()
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timeout = t.C
		}
		select {
		case p := <-c.recv:
			if len(p) > len(b) {
				return 0, io.ErrShortBuffer
			}
			return copy(b, p), nil
		case <-c.done:
			c.mu.Lock()
			err := c.closeErr
			c.mu.Unlock()
			if err != nil {
				return 0, err
			}
			select {
			case p := <-c.recv: // what came before the end
				if len(p) > len(b) {
					return 0, io.ErrShortBuffer
				}
				return copy(b, p), nil
			default:
				return 0, io.EOF
			}
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-wake:
		}
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	closed, err, wdl := c.closed, c.closeErr, c.wdl
	c.mu.Unlock()
	switch {
	case err != nil:
		return 0, err
	case closed:
		return 0, net.ErrClosed
	case !wdl.IsZero() && !time.Now().Before(wdl):
		return 0, os.ErrDeadlineExceeded
	}
	c.send(b)
	return len(b), nil
}

// Close ends the flow; Read and Write then fail net.ErrClosed.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closeErr != nil {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.closeErr = net.ErrClosed
	if !c.closed {
		c.closed = true
		close(c.done)
	}
	c.mu.Unlock()
	c.stop()
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.local }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	close(c.rdlWake)
	c.rdlWake = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	c.mu.Unlock()
	return nil
}

// ReadFrom is Read, from RemoteAddr.
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.remote, err
}

// WriteTo is Write: the flow has one peer, addr is ignored.
func (c *Conn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }
