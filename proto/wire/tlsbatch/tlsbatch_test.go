// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package tlsbatch

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
)

// countingConn counts the writes that reach the network.
type countingConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, DNSNames: []string{"t"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// pair returns a batched server conn over a counting network conn and a
// client conn (through ClientCredentials, so both sides are exercised).
func pair(t *testing.T) (*Conn, *countingConn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	cert := testCert(t)
	type res struct {
		c   *Conn
		raw *countingConn
	}
	srv := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srv <- res{}
			return
		}
		raw := &countingConn{Conn: c}
		srv <- res{Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}), raw}
	}()
	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	creds := ClientCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // test cert
	s := <-srv
	if s.c == nil {
		t.Fatal("accept failed")
	}
	hs := make(chan error, 1)
	go func() { hs <- s.c.Conn.(*tls.Conn).Handshake() }()
	cc, _, err := creds.ClientHandshake(context.Background(), "t", nc)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-hs; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close(); _ = s.c.Close() })
	return s.c, s.raw, cc
}

func TestBatchedWriteIsOneNetworkWrite(t *testing.T) {
	sc, raw, cc := pair(t)
	msg := make([]byte, 256<<10)
	_, _ = rand.Read(msg)

	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, len(msg))
		_, _ = io.ReadFull(cc, b)
		got <- b
	}()
	before := raw.writes.Load()
	if n, err := sc.Write(msg); err != nil || n != len(msg) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if w := raw.writes.Load() - before; w != 1 {
		t.Fatalf("a %d-byte Write took %d network writes; want 1", len(msg), w)
	}
	if !bytes.Equal(<-got, msg) {
		t.Fatal("client read different bytes")
	}

	// A one-record Write goes straight through, and the client's batched
	// writes reach the server intact.
	before = raw.writes.Load()
	if _, err := sc.Write([]byte("small")); err != nil {
		t.Fatal(err)
	}
	if w := raw.writes.Load() - before; w != 1 {
		t.Fatalf("small Write took %d network writes", w)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(cc, b); err != nil || string(b) != "small" {
		t.Fatalf("read %q, %v", b, err)
	}
	go func() { _, _ = cc.Write(msg) }()
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(sc, back); err != nil || !bytes.Equal(back, msg) {
		t.Fatalf("server read: %v", err)
	}
}

func TestBatchedWriteReportsNetworkError(t *testing.T) {
	sc, raw, _ := pair(t)
	_ = raw.Conn.Close()
	if _, err := sc.Write(make([]byte, 64<<10)); err == nil {
		t.Fatal("Write on a closed network conn must fail")
	}
}

// Close cuts off a batched Write the peer stopped reading, as tls.Conn does
// for its own Writes, instead of queueing the close alert behind it.
func TestCloseDuringBlockedBatchReturns(t *testing.T) {
	sc, _, _ := pair(t) // the client never reads
	wrote := make(chan error, 1)
	go func() {
		big := make([]byte, 1<<20)
		for {
			if _, err := sc.Write(big); err != nil {
				wrote <- err
				return
			}
		}
	}()
	time.Sleep(200 * time.Millisecond) // socket buffers full: the batch blocks
	closed := make(chan struct{})
	go func() {
		_ = sc.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited behind a blocked batched Write")
	}
	select {
	case err := <-wrote:
		if err == nil {
			t.Fatal("the blocked Write must fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the blocked Write did not return after Close")
	}
}

type countingListener struct {
	net.Listener
	conns chan *countingConn
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cc := &countingConn{Conn: c}
	l.conns <- cc
	return cc, nil
}

// TestBatchedHijackedConn: NewHTTPListener's conns are *tls.Conn (net/http
// needs that for HTTP/2) and batch once Batched, as a hijacked connection
// does; any other conn comes back as is.
func TestBatchedHijackedConn(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := countingListener{Listener: inner, conns: make(chan *countingConn, 1)}
	ln := NewHTTPListener(cl, &tls.Config{Certificates: []tls.Certificate{testCert(t)}})
	defer ln.Close() //nolint:errcheck
	go func() {
		c, err := tls.Dial("tcp", inner.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test cert
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck
		_, _ = io.Copy(io.Discard, c)
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	tc, ok := c.(*tls.Conn)
	if !ok {
		t.Fatalf("accepted %T, want *tls.Conn", c)
	}
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	raw := <-cl.conns
	bc := Batched(c)
	before := raw.writes.Load()
	if _, err := bc.Write(make([]byte, 256<<10)); err != nil {
		t.Fatal(err)
	}
	if w := raw.writes.Load() - before; w != 1 {
		t.Fatalf("a batched hijacked conn took %d network writes, want 1", w)
	}
	plain := tls.Client(raw.Conn, &tls.Config{})
	if Batched(plain) != net.Conn(plain) {
		t.Fatal("Batched changed a conn from elsewhere")
	}
}

// TestCloseWriteEndsOnlyWrites: CloseWrite (link's graceful close) lets
// the peer read every byte, then io.EOF, while this side reads on.
func TestCloseWriteEndsOnlyWrites(t *testing.T) {
	c, _, peer := pair(t)
	msg := bytes.Repeat([]byte("x"), 3*recordPayload)
	go func() {
		_, _ = c.Write(msg)
		_ = c.CloseWrite()
	}()
	got, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("peer read %d of %d bytes, then %v; want every byte, then io.EOF", len(got), len(msg), err)
	}
	if _, err := peer.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ok" {
		t.Fatalf("read after CloseWrite: %q %v", b, err)
	}
}

// TestConnectionStateCarriesClientCertificate: a server reads the client
// certificate of a batched conn (the relay's mTLS identity provider).
func TestConnectionStateCarriesClientCertificate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	srvCert, cliCert := testCert(t), testCert(t)
	l := NewListener(ln, &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequestClientCert})
	got := make(chan tls.ConnectionState, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- tls.ConnectionState{}
			return
		}
		defer c.Close() //nolint:errcheck
		bc := c.(*Conn)
		if err := bc.HandshakeContext(context.Background()); err != nil {
			got <- tls.ConnectionState{}
			return
		}
		got <- bc.ConnectionState()
	}()
	cc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cliCert}}) //nolint:gosec // test cert
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close() //nolint:errcheck
	st := <-got
	if !st.HandshakeComplete || len(st.PeerCertificates) != 1 || !bytes.Equal(st.PeerCertificates[0].Raw, cliCert.Certificate[0]) {
		t.Fatalf("server state: handshake %v, %d peer certificates; want the client's one", st.HandshakeComplete, len(st.PeerCertificates))
	}
	if (&Conn{Conn: &net.TCPConn{}}).ConnectionState().HandshakeComplete {
		t.Fatal("a conn that is not TLS reports a TLS state")
	}
}
