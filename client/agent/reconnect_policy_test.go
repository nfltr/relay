// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/client/rpcclient"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// scriptedRelay accepts every ConnectHTTP stream; the first stream is held
// open until the test ends it, every later one ends with next() (the error
// the agent's cycle then returns).
type scriptedRelay struct {
	pb.UnimplementedDispatcherServer
	dials atomic.Int32
	drop  chan struct{}
	next  func() error
}

func (s *scriptedRelay) ConnectHTTP(stream grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest]) error {
	_ = stream.SendHeader(metadata.Pairs("x-resolved-agent-id", "resolved"))
	if s.dials.Add(1) == 1 {
		select {
		case <-s.drop:
			return status.Error(codes.Unavailable, "relay restarting")
		case <-stream.Context().Done():
			return nil
		}
	}
	return s.next()
}

func startScripted(t *testing.T, next func() error) (*scriptedRelay, *agent, context.CancelFunc) {
	t.Helper()
	s := &scriptedRelay{drop: make(chan struct{}), next: next}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDispatcherServer(srv, s)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	ctx, cancel := context.WithCancel(context.Background())
	a := New(Config{ServerAddr: ln.Addr().String(), AgentID: "policy", Retries: 1, Logger: slog.New(slog.DiscardHandler)}).(*agent)
	if err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	for s.dials.Load() < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	return s, a, cancel
}

// Errors the old allow-list ended the agent on redial now.
func TestReconnectRedialsOnUnfamiliarErrors(t *testing.T) {
	for name, err := range map[string]error{
		"unknown code":           status.Error(codes.Unknown, "something unfamiliar"),
		"other failed precond.":  status.Error(codes.FailedPrecondition, "services conflict"),
		"relay silent (wrapped)": status.Error(codes.Unknown, fmt.Sprintf("%v", rpcclient.ErrRelaySilent)),
		"deadline":               status.Error(codes.DeadlineExceeded, "slow"),
		"unimplemented":          status.Error(codes.Unimplemented, "nope"),
	} {
		t.Run(name, func(t *testing.T) {
			s, a, _ := startScripted(t, func() error { return err })
			close(s.drop)
			deadline := time.After(5 * time.Second)
			for s.dials.Load() < 3 {
				select {
				case <-a.Done():
					t.Fatalf("agent stopped with %v after %d dials; want it to keep redialling", a.Err(), s.dials.Load())
				case <-deadline:
					t.Fatalf("only %d dials; want a redial", s.dials.Load())
				case <-time.After(10 * time.Millisecond):
				}
			}
		})
	}
}

func TestReconnectStopsOnFatalClasses(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		hint string
	}{
		"auth":          {status.Error(codes.Unauthenticated, "bad key"), "API key"},
		"permission":    {status.Error(codes.PermissionDenied, "no"), "API key"},
		"version":       {status.Error(codes.FailedPrecondition, agentwire.ClientGenerationTooOld), "update"},
		"relay too old": {status.Error(codes.FailedPrecondition, agentwire.RelayTooOld), "update"},
		"config":        {status.Error(codes.InvalidArgument, "bad"), "configuration"},
		"replaced":      {status.Error(codes.FailedPrecondition, "this session was replaced by a newer one"), "agent ID"},
	} {
		t.Run(name, func(t *testing.T) {
			s, a, _ := startScripted(t, func() error { return c.err })
			close(s.drop)
			select {
			case <-a.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("agent did not stop on a fatal error")
			}
			err := a.Err()
			if err == nil || !strings.Contains(err.Error(), c.hint) || status.Code(err) != status.Code(c.err) {
				t.Fatalf("Err = %v, want the cause with a hint containing %q", err, c.hint)
			}
			if n := s.dials.Load(); n != 2 {
				t.Fatalf("%d dials, want 2 (first + the refused one)", n)
			}
		})
	}
}

func TestReconnectCancelStopsCleanly(t *testing.T) {
	s, a, cancel := startScripted(t, func() error { return errors.New("unfamiliar") })
	close(s.drop)
	for s.dials.Load() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-a.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop on cancel")
	}
	if err := a.Err(); err != nil {
		t.Fatalf("Err after cancel = %v, want nil", err)
	}
}

// A relay that fails every dial must not be hammered: redials follow the
// bounded backoff (RedialBase 250 ms, flat for 8 redials).
func TestReconnectDoesNotSpin(t *testing.T) {
	s, _, _ := startScripted(t, func() error { return status.Error(codes.Unknown, "boom") })
	close(s.drop)
	time.Sleep(2 * time.Second)
	if n := s.dials.Load(); n > 10 {
		t.Fatalf("%d dials in 2 s; want a bounded rate (<= 10)", n)
	}
	if n := s.dials.Load(); n < 3 {
		t.Fatalf("%d dials in 2 s; want it to keep redialling", n)
	}
}
