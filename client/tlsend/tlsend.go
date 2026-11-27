// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package tlsend tells a TLS peer's end of its stream (close_notify) from
// the transport's end. crypto/tls reports both as io.EOF, so a relay that
// cuts an end-to-end encrypted session between two records would read as
// the peer's clean end; a Conn reports that cut as ErrTruncated (claims
// review CLAIMS-A Q5; spec/proverif/README.md e2ee_tcp queries 11-12).
// Its Reset is the other half: an end that aborts closes the transport
// without close_notify, so the peer reads a reset, never a clean end
// (lane TCPRESET, queries 15-16).
package tlsend

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// ErrTruncated is a TLS stream whose transport ended without the peer's
// close_notify: whoever carries the transport cut it. Treat it as a reset.
var ErrTruncated = errors.New("tls: the stream ended without the peer's close_notify (cut in transit)")

// Conn is a *tls.Conn whose Read returns ErrTruncated, not io.EOF, after
// a transport end the peer did not announce.
type Conn struct {
	*tls.Conn
	raw *rawEnd
}

// Client is tls.Client over raw, its end checked.
func Client(raw net.Conn, cfg *tls.Config) *Conn {
	r := &rawEnd{Conn: raw}
	return &Conn{tls.Client(r, cfg), r}
}

// Server is tls.Server over raw, its end checked.
func Server(raw net.Conn, cfg *tls.Config) *Conn {
	r := &rawEnd{Conn: raw}
	return &Conn{tls.Server(r, cfg), r}
}

// Wrap prepares raw for a TLS connection the caller makes on the returned
// conn (tls.Client(w, cfg), or a handshake helper that does): bind then
// makes that connection a Conn whose end is checked as Client's is.
func Wrap(raw net.Conn) (w net.Conn, bind func(*tls.Conn) *Conn) {
	r := &rawEnd{Conn: raw}
	return r, func(tc *tls.Conn) *Conn { return &Conn{tc, r} }
}

// Reset ends the connection as failed: no close_notify; the transport is
// reset (its Reset, an RST on a *net.TCPConn) or else closed, which the
// peer's Conn reads as ErrTruncated. peerlink.Join calls it to pass on
// the other side's reset; Close after it sends nothing.
func (c *Conn) Reset() error {
	c.raw.reset.Store(true)
	switch r := c.raw.Conn.(type) {
	case interface{ Reset() error }:
		return r.Reset()
	case *net.TCPConn:
		_ = r.SetLinger(0)
	}
	return c.raw.Conn.Close()
}

// CloseWrite is the half close: the close_notify, then the transport's
// (a link session's FIN), so the peer's reads and its Close take both
// (spec/TLSEnd.tla XNotify, XFin; lane PIPERESET: crypto/tls's alone left
// the FIN to Close, and a peer's Close waited for it).
func (c *Conn) CloseWrite() error {
	if err := c.Conn.CloseWrite(); err != nil {
		return err
	}
	c.trace("Notify", 0) // spec/TraceTLSEnd.tla XNotify
	if cw, ok := c.raw.Conn.(interface{ CloseWrite() error }); ok {
		c.trace("Fin", 0) // XFin
		return cw.CloseWrite()
	}
	return nil
}

// CloseWriteSync is the half close (close_notify), then, on a transport
// that syncs its end (a relayed link session), its CloseWriteSync: nil
// once the far end took the close_notify and the end (link FeatureEndAck;
// else the relay's read of them, link Sync).
func (c *Conn) CloseWriteSync() error { return c.CloseWriteSyncReceived(func() {}) }

// CloseWriteSyncReceived is CloseWriteSync that also reports the next
// hop's receipt where the transport does (link and quiclink
// CloseWriteSyncReceived): received runs there, before the far end's
// acknowledgement, so a peerlink.Join onto this conn ends its hold at the
// receipt (link spec/HopHold.tla, mutant hold-until-ack); on a transport
// without one it runs once its CloseWriteSync returned nil (or the
// close_notify was written).
func (c *Conn) CloseWriteSyncReceived(received func()) error {
	if err := c.Conn.CloseWrite(); err != nil {
		return err
	}
	c.trace("Notify", 0) // spec/TraceTLSEnd.tla XNotify
	switch s := c.raw.Conn.(type) {
	case interface{ CloseWriteSyncReceived(func()) error }:
		c.trace("Fin", 0) // XFin
		err := s.CloseWriteSyncReceived(received)
		c.traceEnd(err)
		return err
	case interface{ CloseWriteSync() error }:
		c.trace("Fin", 0)
		err := s.CloseWriteSync()
		c.traceEnd(err)
		if err != nil {
			return err
		}
	}
	received()
	return nil
}

// traceEnd logs the end of X's wait (spec/TraceTLSEnd.tla XRecv): 1 clean.
func (c *Conn) traceEnd(err error) {
	if err == nil {
		c.trace("End", 1)
	} else {
		c.trace("End", 0)
	}
}

// Close is the TLS connection's (close_notify, then the transport's
// close), or after Reset only the transport's. After the peer's
// close_notify was read it first takes the end of a transport that
// acknowledges ends (one with CloseWriteSync or CloseWriteSyncReceived:
// its FIN behind the close_notify), within EndBound: a close before it races that FIN, and a
// link peer's CloseWriteSync reads such a close as a reset (link
// ENDACKTRUTH; lane PIPERESET). crypto/tls reads nothing past the
// close_notify.
func (c *Conn) Close() error {
	if c.raw.reset.Load() {
		return c.raw.Conn.Close()
	}
	take := c.raw.notified.Load() && syncsEnd(c.raw.Conn)
	if take {
		c.trace("Close", 1) // spec/TraceTLSEnd.tla YClose
		c.raw.takeEnd()
	} else {
		c.trace("Close", 0)
	}
	c.trace("Closed", 0) // YClosed
	return c.Conn.Close()
}

// syncsEnd: raw acknowledges its end to the peer (a link session, or a
// conn passing its CloseWriteSync on), whose wait reads a whole close
// before it as a reset. A direct path's conn ends its own way (its Close
// waits for the peer's end in the background).
func syncsEnd(raw net.Conn) bool {
	switch raw.(type) {
	case interface{ CloseWriteSyncReceived(func()) error }, interface{ CloseWriteSync() error }:
		return true
	}
	return false
}

// EndBound bounds Close's wait for the transport's end after the peer's
// close_notify, as crypto/tls bounds its own close_notify's write (5 s):
// a peer that ends only its TLS stream (CloseWrite) and keeps the
// transport costs a Close no more.
const EndBound = 5 * time.Second

// Read is the TLS connection's, with a transport end as ErrTruncated.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == io.EOF {
		if c.raw.ended.Load() {
			err = ErrTruncated
		} else {
			if !c.raw.notified.Swap(true) {
				c.trace("EOF", 0) // spec/TraceTLSEnd.tla YRecv of the close_notify
			}
		}
	}
	return n, err
}

// rawEnd is the transport under the TLS connection. It hands crypto/tls
// an EOF only on a read of its own, never with the last bytes: after a
// close_notify, crypto/tls reads no further, so ended is set only when
// the stream ended before the peer's close_notify was read.
type rawEnd struct {
	net.Conn
	eof      bool // the transport's EOF, held for the next read
	ended    atomic.Bool
	reset    atomic.Bool // Conn.Reset: Close sends no close_notify
	notified atomic.Bool // the peer's close_notify was read (a clean io.EOF)
}

// NetConn is the transport (crypto/tls's NetConn is this rawEnd): a
// caller reaching under the TLS (the relay client's pathStream.MinRTT).
func (r *rawEnd) NetConn() net.Conn { return r.Conn }

// takeEnd reads the transport to its end (the peer's FIN after its
// close_notify; nothing else comes), within EndBound.
func (r *rawEnd) takeEnd() {
	if r.eof || r.ended.Load() {
		return
	}
	_ = r.Conn.SetReadDeadline(time.Now().Add(EndBound))
	b := make([]byte, 512)
	for {
		if _, err := r.Conn.Read(b); err != nil {
			return
		}
	}
}

func (r *rawEnd) Read(p []byte) (int, error) {
	if r.eof {
		r.ended.Store(true)
		return 0, io.EOF
	}
	n, err := r.Conn.Read(p)
	if err == io.EOF {
		if n > 0 {
			r.eof = true
			return n, nil
		}
		r.ended.Store(true)
	}
	return n, err
}
