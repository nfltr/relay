// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"io"
	"testing"
	"time"

	pb "github.com/nfltr/relay/proto/pb"
)

// TestSendLoopTearsDownAgentOnHalfOpenSendEOF guards the actor-0 28-minute
// hang: a send failure on a HALF-OPEN stream (Send returns io.EOF while Recv
// blocks forever with no error) must tear the agent down so the worker's
// retryLoop reconnects and the completed task's terminal status gets
// re-reported.
//
// failingSendStream models the half-open case precisely: Send returns the
// injected error immediately; Recv blocks on an unwritten channel until the
// stream's ctx is cancelled. Before the fix, sendLoop returned on io.EOF
// WITHOUT cancelling a.ctx, "letting recvLoop detect the error naturally" —
// but recvLoop's Recv never returned, so the agent never terminated and the
// worker hung on a dead connection.
func TestSendLoopTearsDownAgentOnHalfOpenSendEOF(t *testing.T) {
	// The stream's own ctx stays alive for the whole test, so Recv would block
	// forever unless the agent's internal cancel propagates through recvLoop's
	// a.ctx.Done() branch — which is exactly what the fix restores.
	streamCtx := t.Context()

	stream := newFailingSendStream(streamCtx, io.EOF)
	agent := NewAgent("agent-halfopen", stream)
	defer agent.Close() //nolint:errcheck

	// Push a frame; sendLoop will call stream.Send → io.EOF.
	go func() {
		_ = agent.sendFrame(&pb.TunnelFrame{
			MessageType:   "a2a-status",
			TransactionId: "txn-halfopen",
			Eom:           true,
		})
	}()

	select {
	case <-agent.Done():
		// Agent terminated → recvLoop exited → retryLoop will re-dial. Pass.
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not terminate after a half-open send EOF: recvLoop hung on Recv " +
			"and the connection loop never returned (the actor-0 hang). sendLoop must cancel on send failure.")
	}

	if err := agent.Err(); err == nil {
		t.Error("expected agent.Err() to record the send failure so the worker treats it as retryable")
	}
}

// TestSendLoopCloseUnblocksWhenStreamSendHangs guards orchestrator-test and
// half-open production hangs: Agent.Close must not Wait forever while
// stream.Send is blocked. sendLoop races Send against a.ctx so cancel
// completes teardown even when the transport never returns.
func TestSendLoopCloseUnblocksWhenStreamSendHangs(t *testing.T) {
	streamCtx, streamCancel := context.WithCancel(context.Background())
	t.Cleanup(streamCancel)
	ms := newGatedSendStream(streamCtx)
	agent := NewAgent("agent-blocked-send", ms)

	stream, err := agent.NewStream(context.Background(), testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	sendDone := make(chan error, 1)
	go func() { sendDone <- stream.Send([]byte("stuck")) }()
	select {
	case <-ms.dataStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("data send never entered gated stream.Send")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- agent.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Agent.Close hung while stream.Send was blocked; sendLoop must select on a.ctx")
	}
	// Release the gated Send so the orphaned sender goroutine can exit.
	close(ms.releaseData)
	select {
	case <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("blocked stream.Send did not return after release")
	}
}
