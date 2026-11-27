// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The relay closing the tunnel, even cleanly (draining for a deploy), ends
// every pending call with ErrConnectionClosed, never io.EOF: io.EOF is the
// peer ending the call, and a caller confirming delivery by it would take a
// lost connection for a confirmation.
func TestCleanConnectionCloseEndsPendingStreamsWithConnectionClosed(t *testing.T) {
	t.Parallel()
	ms := newMockStream(t.Context())
	agent := NewAgent("agent-a", ms)
	t.Cleanup(func() { _ = agent.Close() })

	stream, err := agent.NewStream(context.Background(), testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	recvErr := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		recvErr <- err
	}()
	close(ms.recvCh) // the relay ends the tunnel: its Recv returns io.EOF

	select {
	case err := <-recvErr:
		if !errors.Is(err, ErrConnectionClosed) || errors.Is(err, io.EOF) {
			t.Fatalf("Recv() error = %v, want ErrConnectionClosed (not io.EOF)", err)
		}
		if !IsRetryableTransportError(err) || status.Code(err) != codes.Unavailable {
			t.Fatalf("Recv() error = %v (code %v), want a retryable Unavailable transport loss", err, status.Code(err))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv() did not unblock after the connection closed")
	}
	if err := agent.Err(); !errors.Is(err, ErrConnectionClosed) || !IsRetryableTransportError(fmt.Errorf("relay connection closed: %w", err)) {
		t.Fatalf("Err() = %v, want a retryable ErrConnectionClosed: reconnect paths must redial", err)
	}
	if _, err := stream.Header(); !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("Header() error = %v, want ErrConnectionClosed", err)
	}
	// A stream opened on the closed connection ends the same way.
	late, err := agent.NewStream(context.Background(), testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	if _, err := late.Recv(); !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("late Recv() error = %v, want ErrConnectionClosed", err)
	}
}

// The peer ending the call before the connection closes still reads io.EOF.
func TestPeerEndBeforeConnectionCloseStaysEOF(t *testing.T) {
	t.Parallel()
	ms := newMockStream(t.Context())
	agent := NewAgent("agent-a", ms)
	t.Cleanup(func() { _ = agent.Close() })

	stream, err := agent.NewStream(context.Background(), testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	if err := stream.Send([]byte("hello")); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	txn := (<-ms.sendCh).GetTransactionId()
	ms.recvCh <- &pb.TunnelFrame{MessageType: "a2a-status", TransactionId: txn, Eom: true}
	close(ms.recvCh)
	<-agent.Done()

	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("Recv() error = %v, want io.EOF: the peer ended the call first", err)
	}
}

// A close whose cause wraps io.EOF (a send that hit the closed stream) must
// not read as the peer ending the call.
func TestConnectionClosedHidesEOFCause(t *testing.T) {
	t.Parallel()
	err := connectionClosedError{cause: fmt.Errorf("rpcclient: send: %w", io.EOF)}
	if errors.Is(err, io.EOF) || !errors.Is(err, ErrConnectionClosed) || status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v: Is(EOF)=%v Is(closed)=%v code=%v", err, errors.Is(err, io.EOF), errors.Is(err, ErrConnectionClosed), status.Code(err))
	}
	broken := connectionClosedError{cause: status.Error(codes.Unavailable, "transport is closing")}
	if !errors.Is(broken, ErrConnectionClosed) || status.Code(broken) != codes.Unavailable {
		t.Fatalf("broken = %v, want ErrConnectionClosed carrying the cause's status", broken)
	}
}

// TestStreamEndStopsAgentLoops: once the relay ends the tunnel the agent is
// dead, so its send and heartbeat loops end too, Close or not (a caller that
// dropped the agent leaked both goroutines).
func TestStreamEndStopsAgentLoops(t *testing.T) {
	t.Parallel()
	ms := newMockStream(t.Context())
	agent := NewAgent("agent-a", ms)
	t.Cleanup(func() { _ = agent.Close() })
	close(ms.recvCh)
	<-agent.Done()

	loops := make(chan struct{})
	go func() { agent.wg.Wait(); close(loops) }()
	select {
	case <-loops:
	case <-time.After(2 * time.Second):
		t.Fatal("send and heartbeat loops still run after the tunnel ended")
	}
}
