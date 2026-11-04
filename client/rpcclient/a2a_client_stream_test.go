// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/handoff"
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

// A caller that takes none of its responses holds only its own call: with
// its window full the receive loop still delivers the agent's other calls
// at once (the code before waited handoff.Stall here when the stalled
// call's next frame came first), and a frame past the window (a peer that
// broke the credit rules) refuses that call alone, without waiting.
func TestClientStream_SaturatedStreamDoesNotBlockOtherTransactions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), handoff.Stall/2)
	defer cancel()

	ms := &mockStream{
		sendCh: make(chan *pb.TunnelFrame, 4),
		recvCh: make(chan *pb.TunnelFrame, ResponseWindow+2),
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

	for i := range ResponseWindow + 1 { // the last one past the window
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

	resp, err := healthy.Recv()
	if err != nil {
		t.Fatalf("healthy Recv: %v (blocked behind the saturated stream)", err)
	}
	if string(resp.Data) != "healthy-response" {
		t.Fatalf("healthy payload = %q", resp.Data)
	}
	for i := range ResponseWindow {
		if _, err := stalled.Recv(); err != nil {
			t.Fatalf("stalled Recv(%d): %v", i, err)
		}
	}
	if _, err := stalled.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("stalled terminal Recv error = %v, want ResourceExhausted", err)
	}
	// The refused call's target is told to stop.
	for f := range ms.sendCh {
		if f.GetTransactionId() == stalledTxn && f.GetMessageType() == "cancel" {
			break
		}
	}
}

// Responses within the window, arriving before the caller reads any, all
// wait in the call's buffer; each quarter window the caller reads goes back
// to the target as one window update.
func TestClientStream_WindowFillsAndGrantsBack(t *testing.T) {
	ms := newMockStream(t.Context())
	ms.recvCh = make(chan *pb.TunnelFrame, ResponseWindow)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck
	stream, err := agent.NewStream(t.Context(), testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	txn := stream.(*clientStream).txnID
	for i := range ResponseWindow {
		ms.recvCh <- &pb.TunnelFrame{Payload: fmt.Appendf(nil, "%d", i), MessageType: "a2a-response", TransactionId: txn}
	}
	for i := range ResponseWindow {
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv %d: %v", i, err)
		}
		if string(resp.Data) != fmt.Sprint(i) {
			t.Fatalf("Recv %d = %q", i, resp.Data)
		}
	}
	for granted := 0; granted < ResponseWindow; {
		f := <-ms.sendCh
		if f.GetMessageType() != WindowMessageType || f.GetTransactionId() != txn {
			continue
		}
		if f.GetRouting().GetTargetAgentId() != testTargetAgentId {
			t.Fatalf("window update routed to %q", f.GetRouting().GetTargetAgentId())
		}
		n, _ := binary.Uvarint(f.GetPayload())
		if n != ResponseWindow/4 {
			t.Fatalf("window update of %d, want a quarter window", n)
		}
		granted += int(n)
	}
	ms.recvCh <- &pb.TunnelFrame{MessageType: "a2a-status", TransactionId: txn, Eom: true}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("Recv after the call's end = %v, want EOF", err)
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
				if dataFrames%(ResponseWindow/4) == 0 { // the caller's reads, granted back
					mock.recvCh <- windowFrame("txn-concurrent", ResponseWindow/4)
				}
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

// windowFrame is a peer's window update for n frames of txn.
func windowFrame(txn string, n int) *pb.TunnelFrame {
	return &pb.TunnelFrame{MessageType: WindowMessageType, TransactionId: txn, Payload: binary.AppendUvarint(nil, uint64(n))}
}
