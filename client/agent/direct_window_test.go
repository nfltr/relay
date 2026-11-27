// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/quic-go"
	"github.com/nfltr/relay/client/tlsend"
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
// ran faster). It stays there while the target does not read: pathswitch
// grows a session's window toward directMaxWindow only while the reader
// keeps up, so a stalled session holds about tcpDataWindow, not 64 MiB
// at its client and 96 at its agent (lane LINKLEFT).
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
		for sent.Load() < 2*directMaxWindow {
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
	if sent := sent.Load(); sent < tcpDataWindow*3/4 || sent > 2*tcpDataWindow {
		t.Fatalf("a direct session took %d bytes before its writes blocked, want 3/4 of its first window (%d) to twice it: a stalled reader's window does not grow to %d", sent, tcpDataWindow, directMaxWindow)
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

// TestDirectSessionWindowCoversALongFatPath: a direct session's QUIC
// stream window starts at tcpDataWindow and may grow to directMaxWindow
// at both ends (pathswitch's window, above). Fixed at 16 MiB, one
// session's rate was 16 MiB per round trip at most: 0.35 Gbit/s on
// Helsinki -> Singapore (260 ms, lane LONGFAT) on a path carrying 1.2.
func TestDirectSessionWindowCoversALongFatPath(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	r.session(t)
	srv := r.table().direct
	for side, qc := range map[string]*quic.Config{"client": r.d.node.QUICConfig(), "server": srv.node.QUICConfig()} {
		if qc.InitialStreamReceiveWindow != tcpDataWindow || qc.MaxStreamReceiveWindow != directMaxWindow {
			t.Errorf("%s: stream window %d up to %d, want %d up to %d", side, qc.InitialStreamReceiveWindow, qc.MaxStreamReceiveWindow, tcpDataWindow, directMaxWindow)
		}
	}
}

// TestPathStreamMinRTT: a path stream has the round trip of the QUIC
// connection under it, under an nf1 session's TLS too, and none on any
// other stream (a relayed one): pathswitch grows the window only with one.
func TestPathStreamMinRTT(t *testing.T) {
	q := rttConn{rtt: 7 * time.Millisecond}
	for _, tc := range []struct {
		name string
		c    net.Conn
		want time.Duration
	}{
		{"quic", q, q.rtt},
		{"tls over quic", tlsend.Client(q, &tls.Config{}), q.rtt},
		{"relayed", &net.TCPConn{}, 0},
	} {
		if got := (pathStream{Conn: tc.c}).MinRTT(); got != tc.want {
			t.Errorf("%s: MinRTT %v, want %v", tc.name, got, tc.want)
		}
	}
}

type rttConn struct {
	net.Conn
	rtt time.Duration
}

func (c rttConn) MinRTT() time.Duration { return c.rtt }
