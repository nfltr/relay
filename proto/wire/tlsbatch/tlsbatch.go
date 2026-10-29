// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package tlsbatch sends all the TLS records of one Write with a single write
// on the network connection.
//
// crypto/tls hands every record (at most 16 KiB of payload) to its conn on
// its own, and reads about one record per Read. A gRPC transport flushing
// 256 KiB therefore costs 16 write syscalls on the sender and 16 read
// syscalls on the receiver. Under the docker benchmark's 1-CPU budget those
// syscalls were most of the relay's gRPC writer goroutine, the stage that
// limited tunnel throughput.
//
// A batched conn's Write encrypts into one buffer and writes it once; a
// Write of one record goes straight through. The buffer is pooled and held
// only during a Write, so an idle conn holds none.
package tlsbatch

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/credentials"
)

// recordPayload is TLS's largest record payload. A Write no longer than
// this is one record, which a batch cannot save anything on.
const recordPayload = 16 << 10

// recordOverhead bounds the bytes TLS adds to one record (header, content
// type, AEAD tag, TLS 1.2 explicit nonce).
const recordOverhead = 5 + 1 + 16 + 8

// maxPooled is the largest batch buffer returned to the pool.
const maxPooled = 1 << 20

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 64<<10); return &b }}

// rawConn is the network conn below tls.Conn. While a batch is open its
// writes are collected; mu keeps any record TLS writes outside a Write (an
// alert, a key update) in order behind the batch.
type rawConn struct {
	net.Conn

	mu    sync.Mutex
	batch *[]byte
}

func (c *rawConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.batch != nil {
		*c.batch = append(*c.batch, p...)
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *rawConn) begin(n int) {
	b := bufPool.Get().(*[]byte)
	if need := n + (n/recordPayload+1)*recordOverhead; cap(*b) < need {
		*b = make([]byte, 0, need)
	}
	c.mu.Lock()
	c.batch = b
	c.mu.Unlock()
}

func (c *rawConn) end() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.batch
	c.batch = nil
	var err error
	if len(*b) > 0 {
		_, err = c.Conn.Write(*b)
	}
	if cap(*b) <= maxPooled {
		*b = (*b)[:0]
		bufPool.Put(b)
	}
	return err
}

// Conn is a TLS conn (from tls.Server, or from gRPC credentials) whose
// multi-record Writes are batched.
type Conn struct {
	net.Conn
	raw     *rawConn
	writing atomic.Bool
}

// Write encrypts p and sends its records with one write on the network.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) <= recordPayload {
		return c.Conn.Write(p)
	}
	c.writing.Store(true)
	defer c.writing.Store(false)
	c.raw.begin(len(p))
	n, err := c.Conn.Write(p)
	if endErr := c.raw.end(); err == nil {
		err = endErr
	}
	return n, err
}

// Close closes the conn. A Write still sending its batch is cut off first,
// as tls.Conn.Close does for a Write in flight: the close alert would
// otherwise wait behind it (up to tls's 5 s close deadline) when the peer
// stopped reading.
func (c *Conn) Close() error {
	if c.writing.Load() {
		_ = c.raw.Conn.Close()
	}
	return c.Conn.Close()
}

// CloseWrite ends this side's writes (TLS's close_notify): the peer reads
// io.EOF after the bytes written, while this side reads on. A graceful
// close needs it (github.com/nfltr/link's drain): a conn closed while the
// peer still sends resets, losing the bytes in flight to the peer.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// ConnectionState is the TLS state of the conn below c (a server reads its
// client's certificate chain from it); zero when that conn is not TLS.
func (c *Conn) ConnectionState() tls.ConnectionState {
	if s, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return s.ConnectionState()
	}
	return tls.ConnectionState{}
}

// HandshakeContext runs the TLS handshake if it has not run yet (a conn
// from Server or NewListener runs it on its first Read or Write).
func (c *Conn) HandshakeContext(ctx context.Context) error {
	if h, ok := c.Conn.(interface{ HandshakeContext(context.Context) error }); ok {
		return h.HandshakeContext(ctx)
	}
	return nil
}

// Server is tls.Server(conn, cfg) with batched writes.
func Server(conn net.Conn, cfg *tls.Config) *Conn {
	raw := &rawConn{Conn: conn}
	return &Conn{Conn: tls.Server(raw, cfg), raw: raw}
}

// Client is tls.Client(conn, cfg) with batched writes; its handshake runs
// on the first Read or Write, or on its *tls.Conn's HandshakeContext.
func Client(conn net.Conn, cfg *tls.Config) *Conn {
	raw := &rawConn{Conn: conn}
	return &Conn{Conn: tls.Client(raw, cfg), raw: raw}
}

type listener struct {
	net.Listener
	cfg *tls.Config
}

func (l listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.cfg), nil
}

// NewListener is tls.NewListener with batched writes. Its conns are not
// *tls.Conn: use it where the server does not look for one (gRPC over a
// TLS listener), not for net/http, which needs *tls.Conn for HTTP/2.
func NewListener(inner net.Listener, cfg *tls.Config) net.Listener {
	return listener{Listener: inner, cfg: cfg}
}

type httpListener struct {
	net.Listener
	cfg *tls.Config
}

func (l httpListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(&rawConn{Conn: c}, l.cfg), nil
}

// NewHTTPListener is tls.NewListener whose conns stay *tls.Conn, as
// net/http needs, and batch once Batched: a connection an HTTP handler
// hijacked to carry a stream of its own (the relay's TCP data
// connections).
func NewHTTPListener(inner net.Listener, cfg *tls.Config) net.Listener {
	return httpListener{Listener: inner, cfg: cfg}
}

// Batched returns c with batched writes when it is a *tls.Conn from
// NewHTTPListener, and c itself otherwise.
func Batched(c net.Conn) net.Conn {
	if tc, ok := c.(*tls.Conn); ok {
		if raw, ok := tc.NetConn().(*rawConn); ok {
			return &Conn{Conn: tc, raw: raw}
		}
	}
	return c
}

// clientCreds wraps gRPC transport credentials: each connection's
// handshake runs over a rawConn, and the conn it returns batches writes.
type clientCreds struct {
	credentials.TransportCredentials
}

// ClientCredentials returns creds whose connections batch writes.
func ClientCredentials(creds credentials.TransportCredentials) credentials.TransportCredentials {
	return clientCreds{TransportCredentials: creds}
}

func (c clientCreds) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	raw := &rawConn{Conn: conn}
	tc, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, raw)
	if err != nil {
		return nil, nil, err
	}
	return &Conn{Conn: tc, raw: raw}, info, nil
}

func (c clientCreds) Clone() credentials.TransportCredentials {
	return clientCreds{TransportCredentials: c.TransportCredentials.Clone()}
}
