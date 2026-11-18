// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/wire/agentservices"
)

// TestDirectPathWindowIsTheDataWindow: a session on the direct path keeps
// as many bytes in flight as one on the relay link (tcpDataWindow): a
// target that stops reading takes most of that window before the client's
// writes block. The direct path's QUIC stream window was link's
// DefaultWindow (1 MiB) while the relay link's is 16 MiB, so one direct
// transfer moved at most 1 MiB per round trip whatever the path carried
// (nfltr-send between regions, 2026-11-18: 25 MB/s on a 36 ms path that
// carries 1.8 Gbit/s, 5 MB/s on a 159 ms one; relayed, the same transfers
// ran faster).
func TestDirectPathWindowIsTheDataWindow(t *testing.T) {
	target, release := stallTarget(t)
	r := newDirectRigOf(t, DirectOn, agentservices.TCP, target)
	_, tc, events := r.session(t)
	echo(t, tc, 1<<16, func() { waitPath(t, events, PathDirect) })

	_, tc2, events2 := r.session(t)
	if _, err := tc2.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	waitPath(t, events2, PathDirect)
	// The session's writes block once the window is full (pathswitch
	// takes no write deadline): a writer counts what went in, the test
	// reads the count once it stopped growing; the session's Close at the
	// end unblocks the writer.
	var sent atomic.Int64
	wrote := make(chan error, 1)
	go func() {
		chunk := make([]byte, 16<<10)
		for sent.Load() < 2*tcpDataWindow {
			n, err := tc2.Write(chunk)
			sent.Add(int64(n))
			if err != nil {
				wrote <- err
				return
			}
		}
		wrote <- nil
	}()
	for last := int64(-1); last != sent.Load(); {
		last = sent.Load()
		time.Sleep(time.Second)
	}
	if sent := sent.Load(); sent < tcpDataWindow*3/4 {
		t.Fatalf("a direct session took %d bytes before its writes blocked, want at least 3/4 of the data window (%d)", sent, tcpDataWindow)
	}
	// The session ends as an echo's does: every byte taken, both ends.
	release()
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if err := tc2.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, tc2); err != nil {
		t.Fatal(err)
	}
}

// stallTarget is a TCP target whose first connection echoes (the rig's
// first session, to make the pair direct) and whose later ones are never
// read until release, with a small receive buffer: what a session's
// client writes to them stays in flight on the session's path.
func stallTarget(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int32
	released := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
			if n.Add(1) == 1 {
				go func() {
					_, _ = io.Copy(c, c)
					_ = c.(*net.TCPConn).CloseWrite()
				}()
				continue
			}
			_ = c.(*net.TCPConn).SetReadBuffer(4 << 10)
			go func() {
				<-released
				// A 4 KiB buffer drains at delayed-ACK pace on Linux.
				_ = c.(*net.TCPConn).SetReadBuffer(4 << 20)
				_, _ = io.Copy(io.Discard, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return ln.Addr().String(), sync.OnceFunc(func() { close(released) })
}
