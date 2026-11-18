// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// nf1Relay is a plaintext relay stand-in for nf1 addresses with the
// listener l behind it: each data connection's sessions are accepted and
// handed to l; the admitted conn arrives on srv, the relay's end of the
// session on raw (a test cuts it there).
func nf1Relay(t *testing.T, l *nf1.Listener) (Config, <-chan net.Conn, <-chan *dataplane.Session) {
	t.Helper()
	return nf1RelayGated(t, l, nil)
}

// nf1RelayGated is nf1Relay that hands a session to l only once the
// client's ClientHello came (hello set; nil: at once), within 3 s: hello
// says whether it came before.
func nf1RelayGated(t *testing.T, l *nf1.Listener, hello chan<- bool) (Config, <-chan net.Conn, <-chan *dataplane.Session) {
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
		sniff := &helloSniff{Conn: nc, hello: make(chan struct{})}
		if hello != nil {
			nc = sniff
		}
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
			if hello != nil {
				// The ClientHello, or the session's end: a client that waits
				// for the answer first sends none, and its dial's bound ends
				// the session (no fixed wait: a loaded runner's ClientHello
				// came past one of 3 s, relay 34bf45670).
				select {
				case <-sniff.hello:
					hello <- true
				case <-s.Done():
					hello <- false
				}
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
	d := dialer(t, Config{Relay: "relay.example:443", Token: "k"})
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

// A refused nf1 dial closes its session, on every refusal after the open
// (here the kind's, nf1.ErrKind, both ways): built with -tags linkdebug
// (make test-linkdebug) a session left for the GC is a link debug report,
// which fails this package (leakcheck).
func TestNF1RefusalClosesSession(t *testing.T) {
	l, _, err := nf1.Mint("relay.example:443")
	if err != nil {
		t.Fatal(err)
	}
	dg, err := l.WithDatagram()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		l        *nf1.Listener
		datagram bool
	}{{"a stream dial to a datagram address", dg, false}, {"a datagram dial to a stream address", l, true}} {
		cfg, _, _ := nf1Relay(t, tc.l)
		d := dialer(t, cfg)
		c, err := dial(t, d, Target{Kind: AddressTarget, Address: tc.l.Address(), datagram: tc.datagram}, DialOptions{})
		if !errors.Is(err, nf1.ErrKind) {
			if c != nil {
				_ = c.Close()
			}
			t.Fatalf("%s: %v, want nf1.ErrKind", tc.name, err)
		}
	}
}

// helloSniff is the relay's end of a plaintext data connection: seen once
// a TLS ClientHello's record (handshake, version 0x0301, type 1) passed it.
type helloSniff struct {
	net.Conn
	mu    sync.Mutex
	buf   []byte
	seen  bool
	hello chan struct{} // closed at the ClientHello
}

func (c *helloSniff) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.buf = append(c.buf, p[:n]...)
	if i := bytes.Index(c.buf, []byte{0x16, 0x03, 0x01}); !c.seen && i >= 0 && len(c.buf) > i+5 && c.buf[i+5] == 0x01 {
		c.seen = true
		close(c.hello)
	}
	c.mu.Unlock()
	return n, err
}

// The ClientHello goes with the open, before the agent's answer (nfltr
// docs/decisions/nf1-ttfb-2026-11-15.md): the relay stand-in hands the
// session to the listener only once the client's ClientHello passed it. A
// client that waits for the answer first never sends it (the dial fails
// with no answer): the open's round trip through the relay and the agent
// is back.
func TestNF1ClientHelloGoesWithOpen(t *testing.T) {
	l, _, err := nf1.Mint("relay.example:443")
	if err != nil {
		t.Fatal(err)
	}
	sawHello := make(chan bool, 1)
	cfg, srvc, _ := nf1RelayGated(t, l, sawHello)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dialer(t, cfg).DialTarget(ctx, Target{Kind: AddressTarget, Address: l.Address()}, DialOptions{})
	if c != nil {
		defer c.Close() //nolint:errcheck
	}
	if !<-sawHello {
		t.Fatal("no ClientHello before the agent's answer: the client waits for the answer before it starts TLS")
	}
	if err != nil {
		t.Fatal(err)
	}
	srv := <-srvc
	defer srv.Close() //nolint:errcheck
	echoAndHalfCloseWith(t, c, srv)
}

// refusingNF1Relay is a plaintext relay stand-in that refuses every open
// with reason and msg.
func refusingNF1Relay(t *testing.T, reason relayv1.ErrorReason, msg string) Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = ln.Close(); <-done })
	go func() {
		defer close(done)
		for { // every open, held or not, on a data connection of its own
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer nc.Close() //nolint:errcheck
				if _, err := http.ReadRequest(bufio.NewReader(nc)); err != nil {
					return
				}
				mux, err := dataplane.Accept(context.Background(), nc, dataWindow, "allow")
				if err != nil {
					return
				}
				_ = mux.Serve(func(_ *pb.TCPData, s *dataplane.Session) {
					_ = s.AbortWith(dataplane.Refusal(reason, msg))
				})
			}()
		}
	}()
	return Config{Plaintext: true, DialRelay: func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}}
}

// A refused open keeps the relay's reason (exit 4 refused, not 6 reset):
// the ClientHello sent with the open fails at its write, before TLS reads
// the refusal (nf1.AnswerConn.Err; found by the connect conformance suite's
// per-address cap, lane NF1TTFB).
func TestNF1RefusedOpenKeepsItsReason(t *testing.T) {
	cfg := refusingNF1Relay(t, relayv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "over the relay's limit")
	l, _, err := nf1.Mint("relay.example:443")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dialer(t, cfg).DialTarget(ctx, Target{Kind: AddressTarget, Address: l.Address()}, DialOptions{})
	if c != nil {
		_ = c.Close()
	}
	if CodeOf(err) != CodeRefused {
		t.Fatalf("dial: %v (%s), want refused", err, CodeOf(err))
	}
}

// An address no service holds is not_found at once, with or without
// direct paths: the relay's nf1 answer (unknown, offline and every dial
// failed are one) is final, so the dial is not held for the open's bound
// (60 s with direct paths: nfltr cat pipe's DefaultOpenTimeout; lane
// NF1FAST).
func TestNF1NotServedIsNotHeld(t *testing.T) {
	cfg := refusingNF1Relay(t, relayv1.ErrorReason_ERROR_REASON_AGENT_OFFLINE, "no nf1 service at this address")
	l, _, err := nf1.Mint("relay.example:443")
	if err != nil {
		t.Fatal(err)
	}
	for _, direct := range []DirectMode{DirectOff, DirectOn} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		start := time.Now()
		c, err := dialer(t, cfg).DialTarget(ctx, Target{Kind: AddressTarget, Address: l.Address()}, DialOptions{Direct: direct})
		cancel()
		if c != nil {
			_ = c.Close()
		}
		if took := time.Since(start); CodeOf(err) != CodeNotFound || took > 2*time.Second {
			t.Fatalf("direct %q: %v (%s) after %v, want not_found within 2 s", direct, err, CodeOf(err), took)
		}
	}
}
