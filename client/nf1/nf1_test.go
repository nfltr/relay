// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nf1

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/nfltr/relay/client/capaddr"
)

const relay = "relay.example:443"

func mint(t *testing.T) (*Listener, ed25519.PrivateKey) {
	t.Helper()
	l, key, err := Mint(relay)
	if err != nil {
		t.Fatal(err)
	}
	return l, key
}

// run runs server on one end of a pipe and Handshake(addr) on the other:
// the client's conn and error, the server's error.
func run(t *testing.T, addr capaddr.Address, server func(net.Conn) error) (net.Conn, error, error) {
	t.Helper()
	c, s := net.Pipe()
	serr := make(chan error, 1)
	go func() {
		err := server(s)
		if err != nil {
			_ = s.Close()
		}
		serr <- err
	}()
	conn, err := Handshake(context.Background(), c, addr)
	if err != nil {
		_ = c.Close()
	}
	return conn, err, <-serr
}

func TestHandshakeAdmitsAndCarriesBytes(t *testing.T) {
	l, _ := mint(t)
	var srv net.Conn
	conn, err, serr := run(t, l.Address(), func(s net.Conn) (err error) {
		srv, err = l.Accept(context.Background(), s)
		return err
	})
	if err != nil || serr != nil {
		t.Fatalf("Handshake = %v, Accept = %v", err, serr)
	}
	defer conn.(*tls.Conn).NetConn().Close() //nolint:errcheck // a TLS close_notify on a pipe waits for its reader
	defer srv.(*tls.Conn).NetConn().Close()  //nolint:errcheck
	go func() { _, _ = conn.Write([]byte("ping")) }()
	b := make([]byte, 4)
	if _, err := io.ReadFull(srv, b); err != nil || string(b) != "ping" {
		t.Fatalf("server read %q, %v", b, err)
	}
}

func TestReadAnswerBounds(t *testing.T) {
	big := make([]byte, MaxAnswer)
	for _, b := range [][]byte{
		[]byte("nf1x"), appendAnswer(nil, big, nil, nil), []byte("nf1a\x00"),
	} {
		c, s := net.Pipe()
		go func() { _, _ = s.Write(b); _ = s.Close() }()
		if _, _, _, err := readAnswer(c); err == nil {
			t.Errorf("readAnswer(%.8q...) accepted", b)
		}
		_ = c.Close()
	}
	if _, err := NewListener(capaddr.Address{}, nil); err == nil {
		t.Fatal("NewListener accepted no key")
	}
}

// TestAnonymousHint: an anonymous listener signs a1 beside d2 (in the
// order d2, u1, a1, whichever copy adds which); the record covers it; a
// handshake that cannot go direct (Handshake: no framing) refuses an
// anonymous answer with ErrDirectRequired.
func TestAnonymousHint(t *testing.T) {
	l, _ := mint(t)
	a, err := l.WithAnonymous()
	if err != nil {
		t.Fatal(err)
	}
	if a, err = a.WithDirect(); err != nil {
		t.Fatal(err)
	}
	if string(a.hints) != "d2,a1" || !a.Anonymous() || l.Anonymous() || !Anonymous(a.hints) {
		t.Fatalf("hints %q, anonymous %v (original %v)", a.hints, a.Anonymous(), l.Anonymous())
	}
	if err := a.Address().CheckAnswer(a.spki, a.rec, a.hints); err != nil {
		t.Fatalf("the record does not cover the hints: %v", err)
	}
	_, err, _ = run(t, a.Address(), func(s net.Conn) error {
		_, err := a.Accept(context.Background(), s)
		return err
	})
	if !errors.Is(err, ErrDirectRequired) {
		t.Fatalf("Handshake to an anonymous address = %v, want ErrDirectRequired", err)
	}
}

// TestAnonymousEarly: an early session (its ClientHello sent with the
// open, never framed for direct paths) refuses an anonymous answer.
func TestAnonymousEarly(t *testing.T) {
	l, _ := mint(t)
	a, err := l.WithAnonymous()
	if err != nil {
		t.Fatal(err)
	}
	c, s := net.Pipe()
	defer c.Close() //nolint:errcheck
	go func() { _ = a.WriteAnswer(s); _ = s.Close() }()
	ac := EarlyAnswer(c, a.Address(), false, func() error { return nil })
	if err := ac.Err(); !errors.Is(err, ErrDirectRequired) {
		t.Fatalf("Err = %v, want ErrDirectRequired", err)
	}
}

// resetRead is a client conn whose peer's end reads as a reset, as a
// relayed or direct session's ABORT does.
type resetRead struct{ net.Conn }

var errSessionReset = errors.New("session reset")

func (c resetRead) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == io.EOF {
		err = errSessionReset
	}
	return n, err
}

// A session reset after the proof and before the verdict (a listener that
// admits it and then resets it: nfltr-pipe's second dial) is the reset,
// not a refused secret: ClientTLS returns the connection's error, never
// capaddr.ErrProof. The stream's end with no verdict stays the refusal.
func TestResetBeforeVerdictIsNotARefusal(t *testing.T) {
	for _, reset := range []bool{true, false} {
		l, _ := mint(t)
		c, s := net.Pipe()
		go func() {
			defer s.Close() //nolint:errcheck
			tc := tls.Server(s, l.cfg)
			if tc.Handshake() == nil {
				_, _ = io.ReadFull(tc, make([]byte, capaddr.ProofSize))
			}
		}()
		var conn net.Conn = c
		if reset {
			conn = resetRead{c}
		}
		_, err := ClientTLS(context.Background(), conn, l.Address())
		_ = c.Close()
		if reset && (errors.Is(err, capaddr.ErrProof) || !errors.Is(err, errSessionReset)) {
			t.Errorf("a reset before the verdict: %v, want the reset", err)
		}
		if !reset && !errors.Is(err, capaddr.ErrProof) {
			t.Errorf("the end with no verdict: %v, want capaddr.ErrProof", err)
		}
	}
}

// TestOlderDirectHintIsNoDirect (lane DIRECTONCE: the layering a framed
// session has changed): an answer signing "d1", the older hint, takes no
// direct path here, so an older listener's sessions stay plain and
// relayed; this listener signs "d2", which an older client ignores.
func TestOlderDirectHintIsNoDirect(t *testing.T) {
	if TakesDirect([]byte("d1")) || TakesDirect([]byte("d1,a1")) || !TakesDirect([]byte("d2,a1")) {
		t.Fatal("d1 read as this layering's direct paths")
	}
	l, _ := mint(t)
	d, err := l.WithDirect()
	if err != nil || string(d.hints) != "d2" {
		t.Fatalf("hints %q, %v: want d2", d.hints, err)
	}
}

// TestKindRefused: a plain Accept (no direct paths) refuses a framed
// session, which the client reads as ErrKindRefused before its proof;
// AdmitKind takes it, and a plain one.
func TestKindRefused(t *testing.T) {
	l, _ := mint(t)
	for _, c := range []struct {
		kind  byte
		admit bool // AdmitKind, not Admit
		ok    bool
	}{{KindFramed, false, false}, {KindFramed, true, true}, {KindPlain, true, true}, {KindPlain, false, true}} {
		cc, s := net.Pipe()
		serr := make(chan error, 1)
		go func() {
			var err error
			if err = l.WriteAnswer(s); err == nil {
				if c.admit {
					var k byte
					if _, k, err = l.AdmitKind(context.Background(), s); err == nil && k != c.kind {
						err = errors.New("another kind")
					}
				} else {
					_, err = l.Admit(context.Background(), s)
				}
			}
			_ = s.Close()
			serr <- err
		}()
		if _, err := ReadAnswer(cc, l.Address()); err != nil {
			t.Fatal(err)
		}
		_, err := clientTLS(context.Background(), cc, l.Address(), c.kind)
		_ = cc.Close()
		serr2 := <-serr
		if (err == nil) != c.ok || (serr2 == nil) != c.ok || !c.ok && !errors.Is(err, ErrKindRefused) {
			t.Fatalf("kind %q (AdmitKind %v): client %v, server %v, want ok %v", c.kind, c.admit, err, serr2, c.ok)
		}
	}
}
