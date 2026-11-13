// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nf1

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
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
