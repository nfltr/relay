// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package tlsend

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nfltr/link"
)

// sessionPair is X (a Client) and Y (a Server) over one link session
// (FeatureEndAck: a relayed session's end, spec/TLSEnd.tla), handshaken.
func sessionPair(t *testing.T) (x, y *Conn) {
	t.Helper()
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan *link.Session, 1)
	served := make(chan struct{})
	go func() {
		defer close(served)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		lc, _, err := link.Server(ctx, c, link.Config{Auth: link.NoAuth})
		if err != nil {
			_ = c.Close()
			return
		}
		_ = link.NewMux(lc).Serve(func(_ []byte, s *link.Session) { accepted <- s })
	}()
	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	lc, err := link.Client(ctx, nc, link.Config{})
	if err != nil {
		t.Fatal(err)
	}
	m := link.NewMux(lc)
	go func() { _ = m.Serve(nil) }()
	t.Cleanup(func() { _ = lc.Close(); <-served })
	sa, err := m.Open(ctx, []byte("h"))
	if err != nil {
		t.Fatal(err)
	}
	sb := <-accepted
	x = Client(sa, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // #nosec G402 -- test: the test's own certificate
	y = Server(sb, &tls.Config{Certificates: []tls.Certificate{cert(t)}, MinVersion: tls.VersionTLS13})
	done := make(chan error, 1)
	go func() { done <- y.Handshake() }()
	if err := x.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return x, y
}

// TestEndOverALinkSession (spec/TLSEnd.tla; its traces, -tags relaytrace,
// spec/TraceTLSEnd.tla): X ends its stream over a link session, Y reads
// the close_notify's EOF and closes. X's CloseWriteSync returns nil: Y's
// Close took the FIN behind the close_notify before its whole close
// (NoFalseReset; mutant close-at-notify: a reset). closewrite: X's half
// close alone, its Close after Y's; crossing: both end at once.
func TestEndOverALinkSession(t *testing.T) {
	for _, tc := range []string{"sync", "closewrite", "crossing"} {
		t.Run(tc, func(t *testing.T) {
			x, y := sessionPair(t)
			xEnd := make(chan error, 1)
			if tc == "closewrite" {
				xEnd <- x.CloseWrite()
			} else {
				go func() { xEnd <- x.CloseWriteSync() }()
			}
			yEnd := make(chan error, 1)
			if tc == "crossing" {
				go func() { yEnd <- y.CloseWriteSync() }()
			}
			if b, err := io.ReadAll(y); err != nil || len(b) != 0 {
				t.Fatalf("Y read %q, %v; want the close_notify's EOF", b, err)
			}
			if tc == "crossing" {
				if b, err := io.ReadAll(x); err != nil || len(b) != 0 {
					t.Fatalf("X read %q, %v; want the close_notify's EOF", b, err)
				}
				if err := within(t, yEnd, "Y's CloseWriteSync"); err != nil {
					t.Fatalf("Y's CloseWriteSync: %v", err)
				}
			}
			if err := y.Close(); err != nil {
				t.Fatalf("Y's Close: %v", err)
			}
			if err := within(t, xEnd, "X's end"); err != nil {
				t.Fatalf("X's end: %v, want nil (Y took it before its close)", err)
			}
			_ = x.Close()
		})
	}
}

// within is ch's result, bounded only against a hang.
func within(t *testing.T, ch chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: hang", what)
		return nil
	}
}

// TestCloseOnADirectPathTakesNoEnd: Close after the peer's close_notify
// takes the transport's end only on a transport that acknowledges ends
// (syncsEnd: a link session). A direct path's conn ends its own way (its
// Close waits for the peer's end in the background), so Close there
// closes at once, even when the peer keeps its transport: waiting
// EndBound there failed nfltr-pipe's direct dials (exit 6; lane
// PIPERESET, guarded only by pipe's direct cases until lane ENDTRACE;
// Go mutant direct-takes-end).
func TestCloseOnADirectPathTakesNoEnd(t *testing.T) {
	reader, writer, _ := pair(t, true)
	if err := writer.CloseWrite(); err != nil { // the close_notify alone: the transport stays
		t.Fatal(err)
	}
	if b, err := io.ReadAll(reader); err != nil || len(b) != 0 {
		t.Fatalf("read %q, %v; want the close_notify's EOF", b, err)
	}
	start := time.Now()
	_ = reader.Close()
	if d := time.Since(start); d >= EndBound {
		t.Fatalf("Close over a conn without end acknowledgements took %v: it waited for the transport's end", d)
	}
}
