// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package jsconn

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall/js"
	"time"
)

// Conn is a WebSocket or an RTCDataChannel as a net.Conn: binary messages
// both ways, each Write cut into messages of at most max bytes. Neither has
// a half close: a session's is TLS's close_notify inside it. Reads after
// the peer closed return a *CloseError (the WebSocket's code; 0 for a data
// channel).
type Conn struct {
	v      js.Value
	max    int
	notify chan struct{} // a message, the open, a close or a new deadline

	mu       sync.Mutex
	q        [][]byte
	opened   bool
	closed   *CloseError // the peer's close
	local    bool        // Close was called
	rdl, wdl time.Time
}

// New wraps v, a WebSocket or RTCDataChannel that may not be open yet (its
// handlers are set at once, so no message is missed), writing messages of
// at most max bytes.
func New(v js.Value, max int) *Conn {
	c := &Conn{v: v, max: max, notify: make(chan struct{}, 1)}
	v.Set("binaryType", "arraybuffer")
	on := func(event string, f func(ev js.Value)) {
		fn := js.FuncOf(func(_ js.Value, a []js.Value) any { f(a[0]); return nil })
		v.Set(event, fn)
	}
	on("onopen", func(js.Value) { c.update(func() { c.opened = true }) })
	on("onmessage", func(ev js.Value) {
		d := ev.Get("data")
		if d.Type() == js.TypeString { // the relay sends no text: its wire is broken
			c.update(func() { c.closed = &CloseError{Code: CloseUnsupport, Reason: "text message"} })
			v.Call("close")
			return
		}
		b := make([]byte, d.Get("byteLength").Int())
		js.CopyBytesToGo(b, js.Global().Get("Uint8Array").New(d))
		c.update(func() { c.q = append(c.q, b) })
	})
	on("onclose", func(ev js.Value) {
		e := &CloseError{}
		if code := ev.Get("code"); code.Type() == js.TypeNumber {
			e.Code, e.Reason = code.Int(), ev.Get("reason").String()
		}
		c.update(func() {
			if c.closed == nil {
				c.closed = e
			}
		})
	})
	if rs := v.Get("readyState"); rs.Equal(js.ValueOf(1)) || rs.Equal(js.ValueOf("open")) {
		c.opened = true
	}
	return c
}

func (c *Conn) update(f func()) {
	c.mu.Lock()
	f()
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// Closed is the peer's close, nil while open or after only a local Close.
func (c *Conn) Closed() *CloseError {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// wait blocks until ready (under c.mu) holds, the deadline passes or the
// conn closes; it returns with c.mu held on success.
func (c *Conn) wait(ready func() bool, dl *time.Time) error {
	for {
		c.mu.Lock()
		switch {
		case c.local:
			c.mu.Unlock()
			return net.ErrClosed
		case ready():
			return nil
		case c.closed != nil:
			err := c.closed
			c.mu.Unlock()
			return err
		}
		d := *dl
		c.mu.Unlock()
		var expired <-chan time.Time
		if !d.IsZero() {
			left := time.Until(d)
			if left <= 0 {
				return os.ErrDeadlineExceeded
			}
			t := time.NewTimer(left)
			expired = t.C
			defer t.Stop()
		}
		select {
		case <-c.notify:
		case <-expired:
		}
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	if err := c.wait(func() bool { return len(c.q) > 0 }, &c.rdl); err != nil {
		return 0, err
	}
	n := copy(p, c.q[0])
	if c.q[0] = c.q[0][n:]; len(c.q[0]) == 0 {
		c.q = c.q[1:]
	}
	more := len(c.q) > 0
	c.mu.Unlock()
	if more { // another reader may wait on what is left
		select {
		case c.notify <- struct{}{}:
		default:
		}
	}
	return n, nil
}

// ponytail: no backpressure on send (the browser buffers, bufferedAmount
// unbounded); add a bufferedAmountLowThreshold wait if uploads grow large.
func (c *Conn) Write(p []byte) (n int, err error) {
	if err := c.wait(func() bool { return c.opened }, &c.wdl); err != nil {
		return 0, err
	}
	c.mu.Unlock()
	defer func() {
		if r := recover(); r != nil { // send threw (the transport closed under us)
			err = fmt.Errorf("jsconn: send: %v", r)
		}
	}()
	u8 := js.Global().Get("Uint8Array")
	for len(p) > 0 {
		m := p[:min(len(p), c.max)]
		a := u8.New(len(m))
		js.CopyBytesToJS(a, m)
		c.v.Call("send", a)
		n += len(m)
		p = p[len(m):]
	}
	return n, nil
}

// Close closes the transport; reads and writes after it fail.
func (c *Conn) Close() error {
	c.mu.Lock()
	done := c.local
	c.local = true
	c.mu.Unlock()
	if done {
		return net.ErrClosed
	}
	c.v.Call("close")
	select {
	case c.notify <- struct{}{}:
	default:
	}
	// ponytail: the four js.Funcs per transport are never released (a JS
	// event after Release would panic); release them after onclose once a
	// page's session count makes the leak measurable.
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.update(func() { c.rdl, c.wdl = t, t })
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.update(func() { c.rdl = t })
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.update(func() { c.wdl = t })
	return nil
}

type addr string

func (a addr) Network() string { return "browser" }
func (a addr) String() string  { return string(a) }

func (c *Conn) LocalAddr() net.Addr  { return addr("page") }
func (c *Conn) RemoteAddr() net.Addr { return addr("relay") }

var _ net.Conn = (*Conn)(nil)
