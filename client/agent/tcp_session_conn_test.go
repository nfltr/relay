// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/nfltr/relay/client/internal/bytequeue"
	"github.com/nfltr/relay/proto/pb"
)

// sessionConn stands in for net.Pipe under the agent's E2EE TLS server, so
// it must keep the conn semantics http.Server relies on: a read deadline in
// the past stops a blocked Read (http.Server's background read after each
// handler), a cleared deadline lets reads continue, and a close from the
// relay ends reads after the queued bytes.
func TestSessionConnReadDeadlineAndClose(t *testing.T) {
	tt := &tcpTunnel{
		logger:   slog.New(slog.DiscardHandler),
		sendCh:   make(chan *pb.TCPData, 8),
		stop:     make(chan struct{}),
		sendDone: make(chan struct{}),
		sessions: map[string]*bytequeue.Queue{},
	}
	q := tt.openSession("s1")
	c := newSessionConn(tt, "s1", q)

	read := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 8))
		read <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case err := <-read:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read after past deadline = %v, want ErrDeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a past read deadline did not stop a blocked Read")
	}

	_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := c.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read past a future deadline = %v", err)
	}

	_ = c.SetReadDeadline(time.Time{})
	q.Push([]byte("hello"))
	tt.closeSession("s1", q) // the relay closed: queued bytes first, then EOF
	b := make([]byte, 8)
	if n, err := c.Read(b); err != nil || string(b[:n]) != "hello" {
		t.Fatalf("Read = %q, %v", b[:n], err)
	}
	if _, err := c.Read(b); err != io.EOF {
		t.Fatalf("Read after the relay's close = %v, want EOF", err)
	}

	if n, err := c.Write([]byte("resp")); err != nil || n != 4 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if f := <-tt.sendCh; f.GetSessionId() != "s1" || string(f.GetData()) != "resp" {
		t.Fatalf("frame = %v", f)
	}
	_ = c.Close()
	if f := <-tt.sendCh; !f.GetClose() {
		t.Fatalf("Close sent %v, want a close frame", f)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close must fail")
	}
}
