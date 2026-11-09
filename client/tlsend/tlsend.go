// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package tlsend tells a TLS peer's end of its stream (close_notify) from
// the transport's end. crypto/tls reports both as io.EOF, so a relay that
// cuts an end-to-end encrypted session between two records would read as
// the peer's clean end; a Conn reports that cut as ErrTruncated (claims
// review CLAIMS-A Q5; spec/proverif/README.md e2ee_tcp queries 11-12).
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
