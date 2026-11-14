// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nf1

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// fakeRelay serves one data connection on a loopback listener: it answers
// the upgrade, accepts the first session and runs l's server side of the
// handshake on it, handing the admitted conn to srv.
func fakeRelay(t *testing.T, l *Listener) (dial func(context.Context, string) (net.Conn, error), srv <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conns := make(chan net.Conn, 1)
	done := make(chan struct{})
	t.Cleanup(func() { _ = ln.Close(); <-done })
	go func() {
		defer close(done)
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		defer nc.Close() //nolint:errcheck
		if _, err := http.ReadRequest(bufio.NewReader(nc)); err != nil {
			return
		}
		mux, err := dataplane.Accept(context.Background(), nc, window, "allow")
		if err != nil {
			return
		}
		_ = mux.Serve(func(_ *pb.TCPData, s *dataplane.Session) {
			go func() {
				_ = s.Accept()
				c, err := l.Accept(context.Background(), s)
				if err != nil {
					_ = mux.Close()
					return
				}
				conns <- c
			}()
		})
	}()
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}, conns
}

// TestNF1HalfClose: Dial's conn keeps the TLS session's half close
// (close_notify): the server reads EOF after the client's bytes and its
// own bytes still reach the client (nfltr docs/decisions/p2p-sdk-2026-11-14.md
// "Half close"; cat pipe needs it).
func TestNF1HalfClose(t *testing.T) {
	l, _ := mint(t)
	dial, srvc := fakeRelay(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, l.Address(), Options{DialRelay: dial})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("Dial's %T has no CloseWrite", c)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	srv := <-srvc
	defer srv.Close() //nolint:errcheck
	if b, err := io.ReadAll(srv); err != nil || string(b) != "ping" {
		t.Fatalf("server read %q, %v; want ping then EOF", b, err)
	}
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatalf("server write after the client's half close: %v", err)
	}
	if err := srv.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(c); err != nil || string(b) != "pong" {
		t.Fatalf("client read %q, %v; want pong then EOF", b, err)
	}
}
