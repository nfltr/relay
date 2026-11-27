// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"
)

// bridgedAgents is a caller and a handler agent whose streams forward to
// each other in order: a relay that neither drops nor reorders.
func bridgedAgents(t *testing.T, ctx context.Context, handle func(ServerStream) error) *Agent {
	t.Helper()
	src, dst := newMockStream(ctx), newMockStream(ctx)
	caller := NewAgent("agent-a", src)
	target := NewAgent(testTargetAgentId, dst)
	t.Cleanup(func() { _ = caller.Close(); _ = target.Close() })
	target.Handle(handle)
	forward := func(from, to *mockStream) {
		for {
			select {
			case m := <-from.sendCh:
				select {
				case to.recvCh <- m:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
	go forward(src, dst)
	go forward(dst, src)
	return caller
}

// A call whose requests pass RequestWindow and whose responses pass
// ResponseWindow, so each side waits for the other's window update while
// the other direction's frames share their connections
// (spec/CallCreditBoth.tla; its trace under -tags relaytrace takes Grant
// both ways: spec/README.md "CallCredit traces").
func TestCallCreditBothWaysGrant(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second) // only against a hang
	defer cancel()
	const reqs, resps = RequestWindow + 4, ResponseWindow + 1
	caller := bridgedAgents(t, ctx, func(s ServerStream) error {
		for {
			if _, err := s.Recv(); err == io.EOF {
				break
			} else if err != nil {
				return err
			}
		}
		for i := range resps { // past ResponseWindow: the caller's grant
			if err := s.Send(fmt.Appendf(nil, "%d", i)); err != nil {
				return err
			}
		}
		return nil
	})
	cs, err := caller.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatal(err)
	}
	for i := range reqs { // past RequestWindow: the handler's grants
		if err := cs.Send(fmt.Appendf(nil, "%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		if _, err := cs.Recv(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != resps {
		t.Fatalf("%d responses, want %d", n, resps)
	}
}

// A caller that leaves a call whose handler never reads: the handler's
// call ends with it (spec/CallCreditBoth.tla Cancel of a stuck call).
func TestCallCreditCallerLeavesStuckHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second) // only against a hang
	defer cancel()
	started, ended := make(chan struct{}), make(chan struct{})
	caller := bridgedAgents(t, ctx, func(s ServerStream) error {
		close(started)
		<-s.Context().Done() // never reads: the caller's cancel ends it
		close(ended)
		return nil
	})
	callCtx, leave := context.WithCancel(ctx)
	cs, err := caller.NewStream(callCtx, testTargetAgentId)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Send([]byte("r")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("the handler never started")
	}
	leave()
	select {
	case <-ended:
	case <-ctx.Done():
		t.Fatal("the handler's call did not end with its caller")
	}
}

// Two goroutines serve one call past ResponseWindow while its caller reads
// nothing: both wait for credit, and the caller's window updates wake them
// both (spec/CallCreditSenders.tla; its trace under -tags relaytrace takes
// a check that finds no credit and the wake).
func TestCallCreditSendersWaitForTheCaller(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second) // only against a hang
	defer cancel()
	const senders, each = 2, ResponseWindow + 1 // both wait, whichever sent first
	caller := bridgedAgents(t, ctx, func(s ServerStream) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		errs := make(chan error, senders)
		for range senders {
			go func() {
				for i := range each {
					if err := s.Send(fmt.Appendf(nil, "%d", i)); err != nil {
						errs <- err
						return
					}
				}
				errs <- nil
			}()
		}
		for range senders {
			if err := <-errs; err != nil {
				return err
			}
		}
		return nil
	})
	cs, err := caller.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Send([]byte("go")); err != nil {
		t.Fatal(err)
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatal(err)
	}
	waitSendersParked(t, senders)
	n := 0
	for {
		if _, err := cs.Recv(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != senders*each {
		t.Fatalf("%d responses, want %d", n, senders*each)
	}
}
