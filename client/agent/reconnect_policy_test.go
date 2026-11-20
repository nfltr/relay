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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/client/relayoutage"
	"github.com/nfltr/relay/client/rpcclient"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
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
	// admit, when set, refuses stream n (from 1) before accepting it when
	// it returns an error: a relay's refusal at admission (no header).
	admit func(n int32) error

	mu sync.Mutex
	at []time.Time // when each stream came
}

func (s *scriptedRelay) ConnectHTTP(stream grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest]) error {
	if s.admit != nil {
		if err := s.admit(s.dials.Load() + 1); err != nil {
			s.dials.Add(1)
			return err
		}
	}
	_ = stream.SendHeader(metadata.Pairs("x-resolved-agent-id", "resolved"))
	s.mu.Lock()
	s.at = append(s.at, time.Now())
	s.mu.Unlock()
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
	return startScriptedRelay(t, &scriptedRelay{drop: make(chan struct{}), next: next})
}

func startScriptedRelay(t *testing.T, s *scriptedRelay) (*scriptedRelay, *agent, context.CancelFunc) {
	t.Helper()
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
	t.Parallel() // waits on timers and peers, not the CPU: overlaps the others
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
			// A hang guard only: an agent that stops ends a.Done at once,
			// and a loaded machine takes about a second per redial.
			deadline := time.After(30 * time.Second)
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
	t.Parallel() // waits on timers and peers, not the CPU: overlaps the others
	for name, c := range map[string]struct {
		err  error
		hint string
	}{
		"auth":          {status.Error(codes.Unauthenticated, "bad key"), "machine certificate"},
		"permission":    {status.Error(codes.PermissionDenied, "no"), "machine certificate"},
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
// bounded backoff (RedialBase 250 ms, flat for 8 redials), so no two
// streams come closer than RedialBase however fast or loaded the machine
// is, and the agent keeps redialling.
func TestReconnectDoesNotSpin(t *testing.T) {
	s, a, _ := startScripted(t, func() error { return status.Error(codes.Unknown, "boom") })
	close(s.drop)
	deadline := time.After(30 * time.Second) // a hang guard: about a second per redial when loaded
	for s.dials.Load() < 6 {
		select {
		case <-a.Done():
			t.Fatalf("agent stopped with %v after %d dials; want it to keep redialling", a.Err(), s.dials.Load())
		case <-deadline:
			t.Fatalf("%d dials in 30 s; want it to keep redialling", s.dials.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 1; i < len(s.at); i++ {
		if gap := s.at[i].Sub(s.at[i-1]); gap < relayoutage.RedialBase {
			t.Fatalf("stream %d came %s after the one before; want at least RedialBase %s apart", i+1, gap, relayoutage.RedialBase)
		}
	}
}

// credentialEnded is the relay's end of an accepted connection whose
// credential expired (relay-core grpcauth.CredentialEndedStatus of
// identity.ErrExpired).
func credentialEnded(t *testing.T) error {
	t.Helper()
	st, err := status.New(codes.Unauthenticated, "credential expired").
		WithDetails(&errdetails.ErrorInfo{Reason: relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED.String(), Domain: "relay.nfltr.xyz"})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

// The relay ends a connection at the expiry of the certificate it was
// opened with, whatever the holder renewed since (relay-core
// identity.Hold): the agent connects again, presenting its newest
// certificate, and goes on (lane SVCRENEW: an agent that stopped on this
// cut stayed disconnected with a renewed certificate; relay-server spec/MachineAuth.tla
// AgentStopsOnlyRefused).
func TestReconnectAfterCredentialExpiryCut(t *testing.T) {
	t.Parallel()
	cut := credentialEnded(t)
	held := make(chan struct{})
	t.Cleanup(func() { close(held) }) // before the server stops (LIFO)
	var n atomic.Int32
	s, a, _ := startScripted(t, func() error {
		if n.Add(1) == 1 {
			return cut // stream 2: cut at its certificate's expiry
		}
		<-held // stream 3: up
		return nil
	})
	close(s.drop)                            // stream 1 drops: stream 2 comes
	deadline := time.After(30 * time.Second) // a hang guard only
	for s.dials.Load() < 3 || !a.Connected() {
		select {
		case <-a.Done():
			t.Fatalf("agent stopped with %v after an expiry cut; want it to connect again", a.Err())
		case <-deadline:
			t.Fatalf("%d dials, connected %v; want a third stream, connected", s.dials.Load(), a.Connected())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// After an expiry cut the redial decides: a relay that refuses it (the
// certificate expired unrenewed) stops the agent with the refusal, so its
// process exits and is restarted (relay-server spec/MachineAuth.tla
// Refused).
func TestReconnectStopsWhenTheRedialIsRefused(t *testing.T) {
	t.Parallel()
	cut := credentialEnded(t)
	s, a, _ := startScriptedRelay(t, &scriptedRelay{drop: make(chan struct{}), next: func() error { return cut },
		admit: func(n int32) error {
			if n >= 3 {
				return cut // refused at admission: no header
			}
			return nil
		}})
	close(s.drop)
	select {
	case <-a.Done():
	case <-time.After(30 * time.Second):
		t.Fatalf("agent did not stop after %d dials; want it stopped on the refused redial", s.dials.Load())
	}
	if err := a.Err(); status.Code(err) != codes.Unauthenticated || !strings.Contains(err.Error(), "machine certificate") {
		t.Fatalf("Err = %v, want the refusal with its hint", err)
	}
	if n := s.dials.Load(); n != 3 {
		t.Fatalf("%d dials, want 3 (first, the cut one, the refused redial)", n)
	}
}
