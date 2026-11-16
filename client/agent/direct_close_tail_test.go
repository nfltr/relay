// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
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
