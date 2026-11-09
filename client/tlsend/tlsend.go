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

// Close is the TLS connection's (close_notify, then the transport's
// close), or after Reset only the transport's.
func (c *Conn) Close() error {
	if c.raw.reset.Load() {
		return c.raw.Conn.Close()
	}
	return c.Conn.Close()
}

// Read is the TLS connection's, with a transport end as ErrTruncated.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == io.EOF && c.raw.ended.Load() {
		err = ErrTruncated
	}
	return n, err
}

// rawEnd is the transport under the TLS connection. It hands crypto/tls
// an EOF only on a read of its own, never with the last bytes: after a
// close_notify, crypto/tls reads no further, so ended is set only when
// the stream ended before the peer's close_notify was read.
type rawEnd struct {
	net.Conn
	eof   bool // the transport's EOF, held for the next read
	ended atomic.Bool
	reset atomic.Bool // Conn.Reset: Close sends no close_notify
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
