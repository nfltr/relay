// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/rpcclient"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// An account whose prepaid balance is exhausted is refused (and its
// connection ended) typed; the agent says so once and keeps redialing, so
// it comes back by itself after a top-up. Even under codes.Unauthenticated
// the reason decides: never a bad key.
func TestReconnectKeepsRedialingOnBalanceExhausted(t *testing.T) {
	st, err := status.New(codes.Unauthenticated, "balance exhausted: top up on the dashboard to continue").
		WithDetails(&errdetails.ErrorInfo{Reason: relayv1.ErrorReason_ERROR_REASON_BALANCE_EXHAUSTED.String(), Domain: "relay.nfltr.xyz"})
	if err != nil {
		t.Fatal(err)
	}
	s := &scriptedRelay{drop: make(chan struct{}), next: st.Err}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDispatcherServer(srv, s)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	logs := &lockedBuf{}
	a := New(Config{ServerAddr: ln.Addr().String(), AgentID: "policy", Retries: 1, Logger: slog.New(slog.NewTextHandler(logs, nil))}).(*agent)
	if err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	close(s.drop)                            // the cut; every redial is then refused
	deadline := time.After(30 * time.Second) // a hang guard only
	for s.dials.Load() < 4 {
		select {
		case <-a.Done():
			t.Fatalf("agent stopped with %v after %d dials; want it to keep redialing", a.Err(), s.dials.Load())
		case <-deadline:
			t.Fatalf("only %d dials; want redials", s.dials.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if n := strings.Count(logs.String(), rpcclient.BalanceExhaustedHint); n != 1 {
		t.Fatalf("the hint was logged %d times, want once per outage:\n%s", n, logs.String())
	}
}
