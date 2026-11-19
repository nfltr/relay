// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nfltr/link/pathswitch"
)

// TestPSConnCloseDeliversTheTail (lane HALFCLOSE, nfltr
// TestE2EE/organisation_remote_half_close): a client that writes after the
// peer's half close and then closes may lose its stream right after Close
// returns (a one-shot dial closes its relay connection, a CLI exits), so
// Close returns only once the peer holds every byte and the END. It
// returned before the session's writer had sent them, the dial's relay
// connection closed under them, and the agent read nothing, then waited
// out its detach bound.
func TestPSConnCloseDeliversTheTail(t *testing.T) {
	for i := range 50 {
		sc, cc := net.Pipe()
		cfg := pathswitch.Config{Detach: time.Minute}
		srv := newPSConn(pathswitch.Server(pathStream{Conn: sc}, PathRelayed, cfg), sc)
		cli := newPSConn(pathswitch.Client(pathStream{Conn: cc}, PathRelayed, cfg), cc)
		got := make(chan string, 1)
		go func() {
			_, _ = srv.Write([]byte("banner"))
			_ = srv.CloseWrite()
			b, _ := io.ReadAll(srv)
			got <- string(b)
			_ = srv.Close()
		}()
		if b, err := io.ReadAll(cli); err != nil || string(b) != "banner" {
			t.Fatalf("run %d: client read %q %v", i, b, err)
		}
		_, _ = cli.Write([]byte("late"))
		_ = cli.Close()
		if !cli.WaitAcked(cli.Written()+1, 0) {
			t.Fatalf("run %d: Close returned before the peer held the bytes and the END", i)
		}
		select {
		case s := <-got:
			if s != "late" {
				t.Fatalf("run %d: the server read %q after its half close, want \"late\"", i, s)
			}
		case <-time.After(10 * time.Second): // a bound against a hang only
			t.Fatalf("run %d: the server's read never ended", i)
		}
		for _, done := range []<-chan struct{}{srv.Done(), cli.Done()} {
			select {
			case <-done:
			case <-time.After(cfg.Detach + 10*time.Second):
				t.Fatalf("run %d: a session never ended", i)
			}
		}
	}
}

// TestPSConnCloseReportsAnUnackedEnd (lane PIPEMATRIX, nfltr-pipe's
// reliability matrix: kill-dialler-75pct-direct): Close returns an error
// when the session fails before the peer acknowledged every byte and the
// END. It returned nil whatever WaitAcked said, so an nfltr-pipe listener
// whose dialler was killed with a quarter of the stream in flight exited 0
// ("the other side took every byte") once the direct path's liveness ran
// out. Each case's peer goes before acknowledging anything: it vanishes
// (its stream closed, no new one within the detach bound) or resets.
func TestPSConnCloseReportsAnUnackedEnd(t *testing.T) {
	for _, tc := range []struct {
		name string
		gone func(srv *psConn, sc net.Conn)
	}{
		{"vanished", func(_ *psConn, sc net.Conn) { _ = sc.Close() }},
		{"reset", func(srv *psConn, _ net.Conn) { _ = srv.Reset() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, cc := net.Pipe()
			cfg := pathswitch.Config{Detach: 200 * time.Millisecond}
			srv := newPSConn(pathswitch.Server(pathStream{Conn: sc}, PathRelayed, cfg), sc)
			cli := newPSConn(pathswitch.Client(pathStream{Conn: cc}, PathRelayed, cfg), cc)
			tc.gone(srv, sc)
			_, _ = cli.Write([]byte("never acknowledged"))
			done := make(chan error, 1)
			go func() { done <- cli.Close() }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Close returned nil though the peer acknowledged neither the bytes nor the END")
				}
			case <-time.After(psCloseBound + 10*time.Second): // a bound against a hang only
				t.Fatal("Close never returned")
			}
		})
	}
}

// TestPSConnResetReachesAPeerBeforeExit (lane PIPEMATRIX, nfltr-pipe's
// reliability matrix: reader-closes-direct): an end that resets and then
// drops its stream at once (a process that exits after Reset) still
// resets its peer: Reset returns once the peer has the ABORT (bounded).
// It returned at once, the ABORT still queued, and the peer read the
// stream's end as a lost path and waited out its detach bound (30 s)
// before it failed.
func TestPSConnResetReachesAPeerBeforeExit(t *testing.T) {
	for i := range 20 {
		sc, cc := net.Pipe()
		cfg := pathswitch.Config{Detach: 20 * time.Second}
		srv := newPSConn(pathswitch.Server(pathStream{Conn: sc}, PathRelayed, cfg), sc)
		cli := newPSConn(pathswitch.Client(pathStream{Conn: cc}, PathRelayed, cfg), cc)
		read := make(chan error, 1)
		go func() { _, err := io.ReadAll(srv); read <- err }()
		if _, err := cli.Write([]byte("some")); err != nil {
			t.Fatal(err)
		}
		_ = cli.Reset()
		_ = cc.Close() // the process is gone
		select {
		case err := <-read:
			if !errors.Is(err, pathswitch.ErrReset) {
				t.Fatalf("run %d: the peer read %v, want pathswitch.ErrReset", i, err)
			}
		case <-time.After(5 * time.Second): // well inside the detach bound
			t.Fatalf("run %d: the peer did not read the reset within 5 s (it waits for its detach bound)", i)
		}
	}
}
