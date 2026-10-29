// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestClientStream_BuffersBurstResponses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ms := &mockStream{
		sendCh: make(chan *pb.TunnelFrame, 4),
		recvCh: make(chan *pb.TunnelFrame, 128),
		ctx:    ctx,
	}
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	stream, err := agent.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream error: %v", err)
	}
	cs := stream.(*clientStream)

	for range 64 {
		ms.recvCh <- &pb.TunnelFrame{
			Payload:       []byte("chunk"),
			MessageType:   "a2a-response",
			TransactionId: cs.txnID,
		}
	}

	deadline := time.After(250 * time.Millisecond)
	for {
		if got := len(ms.recvCh); got == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("recvCh still buffered %d frames", len(ms.recvCh))
		case <-time.After(10 * time.Millisecond):
		}
	}
	if got := len(cs.responseCh); got != 64 {
		t.Fatalf("responseCh buffered %d frames, want 64", got)
	}
}

func TestClientStream_SaturatedStreamDoesNotBlockOtherTransactions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ms := &mockStream{
		sendCh: make(chan *pb.TunnelFrame, 4),
		recvCh: make(chan *pb.TunnelFrame, clientStreamResponseBufferSize+2),
		ctx:    ctx,
	}
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	stalled, err := agent.NewStream(ctx, "stalled-agent")
	if err != nil {
		t.Fatalf("NewStream(stalled): %v", err)
	}
	healthy, err := agent.NewStream(ctx, "healthy-agent")
	if err != nil {
		t.Fatalf("NewStream(healthy): %v", err)
	}
	stalledTxn := stalled.(*clientStream).txnID
	healthyTxn := healthy.(*clientStream).txnID

	for i := range clientStreamResponseBufferSize + 1 {
		ms.recvCh <- &pb.TunnelFrame{
			Payload:       fmt.Appendf(nil, "stalled-%d", i),
			MessageType:   "a2a-response",
			TransactionId: stalledTxn,
		}
	}
	ms.recvCh <- &pb.TunnelFrame{
		Payload:       []byte("healthy-response"),
		MessageType:   "a2a-response",
		TransactionId: healthyTxn,
	}

	done := make(chan error, 1)
	go func() {
		resp, recvErr := healthy.Recv()
		if recvErr == nil && string(resp.Data) != "healthy-response" {
			recvErr = fmt.Errorf("healthy payload = %q", resp.Data)
		}
		done <- recvErr
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("healthy Recv: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("healthy transaction blocked behind saturated stream")
	}

	for i := range clientStreamResponseBufferSize {
		if _, err := stalled.Recv(); err != nil {
			t.Fatalf("stalled Recv(%d): %v", i, err)
		}
	}
	if _, err := stalled.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("stalled terminal Recv error = %v, want ResourceExhausted", err)
	}
}

func TestClientStream_ContextCancellationRemovesPendingTransaction(t *testing.T) {
	agentCtx := t.Context()
	ms := newMockStream(agentCtx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	streamCtx, cancelStream := context.WithCancel(agentCtx)
	stream, err := agent.NewStream(streamCtx, testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	txnID := stream.(*clientStream).txnID
	cancelStream()
	if _, err := stream.Recv(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Recv() error = %v, want context.Canceled", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := agent.pending.Load(txnID); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cancelled client stream remained in pending transaction registry")
}

// ---------------------------------------------------------------------------
// CloseSend EOM: multiple sends produce N+1 wire messages
// ---------------------------------------------------------------------------

func TestClientStream_ImmediateSend(t *testing.T) {
	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	stream, _ := agent.NewStream(ctx, testTargetAgentId)

	// Send 3 messages, then CloseSend.
	_ = stream.Send([]byte("a"))
	_ = stream.Send([]byte("b"))
	_ = stream.Send([]byte("c"))
	_ = stream.CloseSend()

	// Should produce 4 wire messages: a(Eom=false), b(Eom=false), c(Eom=false), ""(Eom=true).
	var msgs []*pb.TunnelFrame
	for range 4 {
		select {
		case m := <-ms.sendCh:
			msgs = append(msgs, m)
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout: got %d/4 messages", len(msgs))
		}
	}

	if string(msgs[0].GetPayload()) != "a" || msgs[0].GetEom() {
		t.Fatal("msg 0: expected a, Eom=false")
	}
	if string(msgs[1].GetPayload()) != "b" || msgs[1].GetEom() {
		t.Fatal("msg 1: expected b, Eom=false")
	}
	if string(msgs[2].GetPayload()) != "c" || msgs[2].GetEom() {
		t.Fatal("msg 2: expected c, Eom=false")
	}
	if len(msgs[3].GetPayload()) != 0 || !msgs[3].GetEom() {
		t.Fatal("msg 3: expected empty EOM marker")
	}

	// Verify no extra messages.
	select {
	case m := <-ms.sendCh:
		t.Fatalf("unexpected extra message: %v", m)
	case <-time.After(100 * time.Millisecond):
	}
}

// ---------------------------------------------------------------------------
// Interleaved Send→Recv (previously deadlocked with deferred-EOM buffering)
// ---------------------------------------------------------------------------

func TestClientStream_InterleavedSendRecv(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msSource := newMockStream(ctx)
	msTarget := newMockStream(ctx)

	source := NewAgent("agent-a", msSource)
	defer source.Close() //nolint:errcheck

	target := NewAgent(testTargetAgentId, msTarget)
	defer target.Close() //nolint:errcheck

	// Target handler: for each request, send a response before reading the next.
	target.Handle(func(stream ServerStream) error {
		for {
			data, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if err := stream.Send([]byte("ack:" + string(data))); err != nil {
				return err
			}
		}
		return nil
	})

	// Bridge: source ↔ target.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msSource.sendCh:
				if !ok {
					return
				}
				select {
				case msTarget.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msTarget.sendCh:
				if !ok {
					return
				}
				select {
				case msSource.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	stream, err := source.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatal(err)
	}

	// Interleaved: Send → Recv → Send → Recv → CloseSend → Recv(EOF).
	if err := stream.Send([]byte("ping1")); err != nil {
		t.Fatal(err)
	}
	resp1, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv after Send(ping1): %v", err)
	}
	if string(resp1.Data) != "ack:ping1" {
		t.Fatalf("expected ack:ping1, got %q", resp1.Data)
	}

	if err := stream.Send([]byte("ping2")); err != nil {
		t.Fatal(err)
	}
	resp2, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv after Send(ping2): %v", err)
	}
	if string(resp2.Data) != "ack:ping2" {
		t.Fatalf("expected ack:ping2, got %q", resp2.Data)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if err != io.EOF {
		t.Fatalf("expected io.EOF after CloseSend, got %v", err)
	}
}

// TestConcurrentServerStreamSend verifies that multiple goroutines can call
// serverStream.Send concurrently without a data race. This reproduces the
// pattern in the remote-exec agent where stdout and stderr goroutines both
// call stream.Send on the same handler stream.
func TestConcurrentServerStreamSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const numGoroutines = 10
	const numMessages = 50
	totalExpected := numGoroutines * numMessages

	// Use a large buffer so 500+ concurrent Sends don't block.
	mock := &mockStream{
		sendCh: make(chan *pb.TunnelFrame, totalExpected+16),
		recvCh: make(chan *pb.TunnelFrame, 4),
		ctx:    ctx,
	}
	agent := NewAgent("concurrent-sender", mock)
	defer agent.Close() //nolint:errcheck

	// Handler that spawns multiple goroutines all calling Send concurrently.
	agent.Handle(func(stream ServerStream) error {
		var wg sync.WaitGroup
		for g := range numGoroutines {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for i := range numMessages {
					msg := fmt.Sprintf("g%d-m%d", id, i)
					if err := stream.Send([]byte(msg)); err != nil {
						t.Errorf("goroutine %d send %d: %v", id, i, err)
						return
					}
				}
			}(g)
		}
		wg.Wait()
		return nil
	})

	// Deliver a single incoming call to trigger the handler.
	mock.recvCh <- &pb.TunnelFrame{
		TransactionId: "txn-concurrent",
		MessageType:   "a2a-request",
		Payload:       []byte("go"),
		Eom:           true,
		Routing:       &pb.RoutingInfo{AgentId: "source"},
	}

	// Collect all sent frames. The handler sends totalExpected data frames
	// plus 1 a2a-status trailer after the handler returns.
	deadline := time.After(5 * time.Second)
	var dataFrames int
	var gotStatus bool
	for {
		select {
		case f := <-mock.sendCh:
			if f.GetMessageType() == "a2a-status" {
				gotStatus = true
			} else {
				dataFrames++
			}
			if gotStatus && dataFrames == totalExpected {
				goto done
			}
		case <-deadline:
			t.Fatalf("timeout: got %d data frames (expected %d), status=%v",
				dataFrames, totalExpected, gotStatus)
		}
	}
done:
	if dataFrames != totalExpected {
		t.Errorf("expected %d data frames, got %d", totalExpected, dataFrames)
	}
}

// ---------------------------------------------------------------------------
// Full round-trip: client + handler via mock stream bridge
// ---------------------------------------------------------------------------
