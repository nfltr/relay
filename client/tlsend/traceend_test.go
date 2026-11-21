// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package tlsend

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// gatedRaw syncs its end (CloseWriteSync) only once gate closes.
type gatedRaw struct {
	net.Conn
	gate chan struct{}
}

func (r *gatedRaw) CloseWriteSync() error { <-r.gate; return nil }

// TestTraceEndAfterOutOfScopeY (lane TLSENDTRACE): X syncs its end, Y's
// transport acknowledges none (a direct path's), so Y's first step drops
// the trace file; X's End after it records nothing. Under -tags
// relaytrace it wrote to the closed file and panicked ("file already
// closed", relay-core TestNF1AnonSDKEndToEnd).
func TestTraceEndAfterOutOfScopeY(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RELAYTRACE", dir)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc := <-accepted
	t.Cleanup(func() { _ = cc.Close(); _ = sc.Close() })
	raw := &gatedRaw{Conn: cc, gate: make(chan struct{})}
	x := Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // #nosec G402 -- test: the test's own certificate
	y := Server(sc, &tls.Config{Certificates: []tls.Certificate{cert(t)}, MinVersion: tls.VersionTLS13})
	hs := make(chan error, 1)
	go func() { hs <- y.Handshake() }()
	if err := x.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-hs; err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- x.CloseWriteSync() }() // Notify, Fin, then End once gate closes
	if b, err := io.ReadAll(y); err != nil || len(b) != 0 {
		t.Fatalf("read %q, %v; want the close_notify's EOF", b, err)
	}
	close(raw.gate)
	if err := <-ended; err != nil {
		t.Fatal(err)
	}
	_ = y.Close()
	if m, _ := filepath.Glob(filepath.Join(dir, "tlsend-*.ndjson")); len(m) != 0 {
		b, _ := os.ReadFile(m[0])
		t.Fatalf("a trace whose Y acknowledges no end was kept: %s\n%s", m, b)
	}
}
