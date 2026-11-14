// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// nf1Relay is a plaintext relay stand-in for nf1 addresses with the
// listener l behind it: each data connection's sessions are accepted and
// handed to l; the admitted conn arrives on srv, the relay's end of the
// session on raw (a test cuts it there).
func nf1Relay(t *testing.T, l *nf1.Listener) (Config, <-chan net.Conn, <-chan *dataplane.Session) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, raw := make(chan net.Conn, 4), make(chan *dataplane.Session, 4)
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
		mux, err := dataplane.Accept(context.Background(), nc, dataWindow, "allow")
		if err != nil {
			return
		}
		_ = mux.Serve(func(_ *pb.TCPData, s *dataplane.Session) {
			if s.Accept() != nil {
				return
			}
			c, err := l.Accept(context.Background(), s)
			if err != nil {
				_ = mux.Close()
				return
			}
			raw <- s
			srv <- c
		})
	}()
	cfg := Config{Plaintext: true, DialRelay: func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}}
	return cfg, srv, raw
}

func dialNF1Addr(t *testing.T, cfg Config, addr capaddr.Address) *Conn {
	t.Helper()
	c, err := dial(t, dialer(t, cfg), Target{Kind: AddressTarget, Address: addr}, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// An nf1 session keeps both half closes (close_notify), and the relay's
// cut reads as a reset, never as the server's clean end.
func TestNF1Session(t *testing.T) {
	l, _, err := nf1.Mint("relay.example:443")
	if err != nil {
		t.Fatal(err)
	}
	cfg, srvc, raws := nf1Relay(t, l)
	c := dialNF1Addr(t, cfg, l.Address())
	if !c.Info().E2EE {
		t.Error("an nf1 session is not end-to-end encrypted")
	}
	srv := <-srvc
	<-raws
	defer srv.Close() //nolint:errcheck
	echoAndHalfCloseWith(t, c, srv)

	l2, _, _ := nf1.Mint("relay.example:443")
	cfg, srvc, raws = nf1Relay(t, l2)
	c = dialNF1Addr(t, cfg, l2.Address())
	srv = <-srvc
	defer srv.Close() //nolint:errcheck
	if _, err := srv.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = (<-raws).CloseWrite() // the relay ends the server's stream: no close_notify
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if string(b) != "x" || CodeOf(err) != CodeReset {
		t.Fatalf("read %q, %v; want x then a reset", b, err)
	}
}

// echoAndHalfCloseWith: the client's bytes then EOF reach srv, srv's
// answer after it then EOF reach the client.
func echoAndHalfCloseWith(t *testing.T, c *Conn, srv net.Conn) {
	t.Helper()
	_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(srv); err != nil || string(b) != "ping" {
		t.Fatalf("server read %q, %v; want ping then EOF", b, err)
	}
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	_ = srv.(interface{ CloseWrite() error }).CloseWrite()
	if b, err := io.ReadAll(c); err != nil || string(b) != "pong" {
		t.Fatalf("client read %q, %v; want pong then EOF", b, err)
	}
}

func TestNF1HandshakeErrors(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx  context.Context
		err  error
		code Code
	}{
		{context.Background(), capaddr.ErrPin, CodeE2EEPinMismatch},
		{context.Background(), nf1.ErrAnswer, CodeE2EEPinMismatch},
		{context.Background(), capaddr.ErrProof, CodeE2EEClientRefused},
		{ended, io.EOF, CodeUnreachable},
		{context.Background(), io.EOF, CodeReset},
	} {
		if err := handshakeError(tc.ctx, tc.err); CodeOf(err) != tc.code || !errors.Is(err, tc.err) && tc.ctx.Err() == nil {
			t.Errorf("%v: %v, want %s", tc.err, err, tc.code)
		}
	}
	if _, err := dialer(t, Config{Plaintext: true}).DialTarget(context.Background(), Target{Kind: AddressTarget}, DialOptions{Plain: true}); CodeOf(err) != CodeUsage {
		t.Errorf("Plain to an nf1 address: %v, want usage", err)
	}
}

// TestDirectStatsCountNF1Sessions: the direct paths of nf1 sessions (kept
// per address relay) are in DirectStats beside the organisation's: nfltr
// cat perf's relay bytes to an address come from it.
func TestDirectStatsCountNF1Sessions(t *testing.T) {
	l, _, err := nf1.Mint("relay.example:443")
	if err != nil {
		t.Fatal(err)
	}
	d := dialer(t, Config{Relay: "relay.example:443", APIKey: "k"})
	if _, ok := d.DirectStats(); ok {
		t.Fatal("stats before any session asked for a direct path")
	}
	if _, err := d.nf1Direct(l.Address()); err != nil {
		t.Fatal(err)
	}
	st, ok := d.DirectStats()
	if !ok || st.Sessions == nil {
		t.Fatalf("stats %+v, %v: an nf1 relay's direct paths are not counted", st, ok)
	}
}
