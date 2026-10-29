// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInvoke_Unary(t *testing.T) {
	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	// Simulate: RPC server relays request to target, target responds.
	go func() {
		req := <-ms.sendCh // the request (Eom=false, data only)
		txnID := req.TransactionId
		if string(req.GetPayload()) != "hello" {
			t.Errorf("expected 'hello', got %q", req.GetPayload())
		}
		if req.GetEom() {
			t.Error("data message should not have EOM")
		}
		// Drain the CloseSend EOM marker.
		eom := <-ms.sendCh
		if !eom.GetEom() || len(eom.GetPayload()) > 0 {
			t.Error("expected empty EOM marker from CloseSend")
		}
		if req.GetRouting().GetTargetAgentId() != testTargetAgentId {
			t.Error("expected target_agent_id=agent-b")
		}

		// Feed response back.
		ms.recvCh <- &pb.TunnelFrame{
			Payload:       []byte("world"),
			MessageType:   "a2a-response",
			TransactionId: txnID,
			Eom:           true,
		}
	}()

	resp, err := agent.Invoke(ctx, testTargetAgentId, []byte("hello"))
	if err != nil {
		t.Fatalf("Invoke error: %v", err)
	}
	if string(resp) != "world" {
		t.Fatalf("expected 'world', got %q", resp)
	}
}

// ---------------------------------------------------------------------------
// Unary: Invoke returns gRPC status error
// ---------------------------------------------------------------------------

func TestInvoke_Error(t *testing.T) {
	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	go func() {
		req := <-ms.sendCh
		txnID := req.TransactionId
		ms.recvCh <- &pb.TunnelFrame{
			MessageType:   "error",
			TransactionId: txnID,
			Eom:           true,
			StatusCode:    int32(codes.NotFound),
			StatusDetail:  "target agent not connected",
		}
	}()

	_, err := agent.Invoke(ctx, testTargetAgentId, []byte("hello"))
	if err == nil {
		t.Fatal("expected error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", st.Code())
	}
}

// ---------------------------------------------------------------------------

func TestNewStream_SendReturnsTransportFailure(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	agent := NewAgent("agent-a", newFailingSendStream(ctx, errors.New("boom")))
	defer agent.Close() //nolint:errcheck

	stream, err := agent.NewStream(context.Background(), testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	if err := stream.Send([]byte("hello")); err == nil {
		t.Fatal("Send() error = nil, want transport failure")
	} else if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Send() error = %v, want boom", err)
	}
}

func TestNewStream_RecvUnblocksWhenAgentStops(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)

	stream, err := agent.NewStream(context.Background(), testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	if err := stream.Send([]byte("hello")); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	recvErrCh := make(chan error, 1)
	go func() {
		_, recvErr := stream.Recv()
		recvErrCh <- recvErr
	}()

	if err := agent.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case recvErr := <-recvErrCh:
		if !errors.Is(recvErr, ErrConnectionClosed) || errors.Is(recvErr, io.EOF) {
			t.Fatalf("Recv() error = %v, want ErrConnectionClosed (not EOF)", recvErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv() did not unblock after agent close")
	}
}

func TestNewStream_HeaderUnblocksWhenTransportFails(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	agent := NewAgent("agent-a", newFailingSendStream(ctx, errors.New("boom")))
	defer agent.Close() //nolint:errcheck

	stream, err := agent.NewStream(context.Background(), testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}

	headerErrCh := make(chan error, 1)
	go func() {
		_, headerErr := stream.Header()
		headerErrCh <- headerErr
	}()

	if err := stream.Send([]byte("hello")); err == nil {
		t.Fatal("Send() error = nil, want transport failure")
	}

	select {
	case headerErr := <-headerErrCh:
		if headerErr == nil || !strings.Contains(headerErr.Error(), "boom") {
			t.Fatalf("Header() error = %v, want boom", headerErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Header() did not unblock after transport failure")
	}
}

func TestNewStream_SendWithE2EEUnblocksWhenAgentStopsBeforeAck(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)
	agent.EnableA2AE2EE()

	stream, err := agent.NewStream(context.Background(), testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}

	sendErrCh := make(chan error, 1)
	go func() {
		sendErrCh <- stream.Send([]byte("hello"))
	}()

	select {
	case frame := <-ms.sendCh:
		if frame.GetMessageType() != a2aE2EEInitMessageType {
			t.Fatalf("first frame type = %q, want %q", frame.GetMessageType(), a2aE2EEInitMessageType)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for A2A E2EE init frame")
	}

	if err := agent.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case sendErr := <-sendErrCh:
		// Close cancels a.ctx; sendLoop may surface that directly (racing
		// stream.Send) or the closed connection. Either unblocks the
		// caller — do not require a single errno.
		if sendErr == nil || (!errors.Is(sendErr, ErrConnectionClosed) && !errors.Is(sendErr, context.Canceled)) {
			t.Fatalf("Send() error = %v, want ErrConnectionClosed or context.Canceled", sendErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("E2EE Send() did not unblock after agent close")
	}
}

// Streaming: NewStream — N requests, M responses
// ---------------------------------------------------------------------------

func TestNewStream_NtoM(t *testing.T) {
	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	// Simulate: target echoes all requests back, then sends status OK.
	go func() {
		var msgs []string
		var txnID string
		for {
			msg := <-ms.sendCh
			txnID = msg.TransactionId
			data := string(msg.GetPayload())
			if len(data) > 0 {
				msgs = append(msgs, data)
			}
			if msg.GetEom() {
				break
			}
		}

		// Send 2 responses + status trailer.
		for i, m := range msgs[:2] {
			ms.recvCh <- &pb.TunnelFrame{
				Payload:       []byte("echo:" + m),
				MessageType:   "a2a-response",
				TransactionId: txnID,
				Routing: &pb.RoutingInfo{
					InitialMetadata: func() map[string]string {
						if i == 0 {
							return map[string]string{"x-version": "1.0"}
						}
						return nil
					}(),
				},
			}
		}
		// Status OK trailer.
		ms.recvCh <- &pb.TunnelFrame{
			MessageType:   "a2a-status",
			TransactionId: txnID,
			Eom:           true,
			StatusCode:    0,
		}
	}()

	stream, err := agent.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatal(err)
	}

	// Send 3 messages.
	for _, d := range []string{"msg1", "msg2", "msg3"} {
		if err := stream.Send([]byte(d)); err != nil {
			t.Fatal(err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}

	// Receive 2 responses.
	var resps []string
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		resps = append(resps, string(resp.Data))
	}
	if len(resps) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(resps))
	}
	if resps[0] != "echo:msg1" || resps[1] != "echo:msg2" {
		t.Fatalf("unexpected responses: %v", resps)
	}

	// Verify initial metadata.
	hdr, err := stream.Header()
	if err != nil {
		t.Fatal(err)
	}
	if hdr["x-version"] != "1.0" {
		t.Fatalf("expected x-version=1.0, got %v", hdr)
	}
}

// ---------------------------------------------------------------------------
// Deadline propagation: context deadline → deadline_ms
// ---------------------------------------------------------------------------

// TestNewStream_HeaderBeforeRecv verifies that Header() works when called
// before Recv(). Previously, Header() would block indefinitely because
// headerCh was only closed inside Recv(). The fix resolves headerCh in
// handleMessage when the first response arrives.
func TestNewStream_HeaderBeforeRecv(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	// Target: read request, send 1 response with metadata + status trailer.
	go func() {
		var txnID string
		for {
			msg := <-ms.sendCh
			txnID = msg.TransactionId
			if msg.GetEom() {
				break
			}
		}

		ms.recvCh <- &pb.TunnelFrame{
			Payload:       []byte("data1"),
			MessageType:   "a2a-response",
			TransactionId: txnID,
			Routing: &pb.RoutingInfo{
				InitialMetadata: map[string]string{"x-test": "header-before-recv"},
			},
		}
		ms.recvCh <- &pb.TunnelFrame{
			MessageType:   "a2a-status",
			TransactionId: txnID,
			Eom:           true,
			StatusCode:    0,
		}
	}()

	stream, err := agent.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send([]byte("req"))
	_ = stream.CloseSend()

	// Key: Header() before Recv() must not deadlock.
	hdr, err := stream.Header()
	if err != nil {
		t.Fatalf("Header() before Recv() failed: %v", err)
	}
	if hdr["x-test"] != "header-before-recv" {
		t.Fatalf("expected x-test=header-before-recv, got %v", hdr)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Data) != "data1" {
		t.Fatalf("expected data1, got %q", string(resp.Data))
	}

	_, err = stream.Recv()
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestNewStream_DeadlinePropagation(t *testing.T) {
	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	// Create a stream with deadline.
	deadline := time.Now().Add(5 * time.Second)
	callCtx, callCancel := context.WithDeadline(ctx, deadline)
	defer callCancel()

	stream, _ := agent.NewStream(callCtx, testTargetAgentId)
	_ = stream.Send([]byte("data"))
	_ = stream.CloseSend()

	// Read the sent data message and verify deadline_ms.
	msg := <-ms.sendCh // "data" with Eom=false
	deadlineMs := msg.GetRouting().GetDeadlineMs()
	if deadlineMs == 0 {
		t.Fatal("expected deadline_ms to be set")
	}
	diff := time.UnixMilli(deadlineMs).Sub(deadline).Abs()
	if diff > 100*time.Millisecond {
		t.Fatalf("deadline_ms mismatch: expected ~%d, got %d (diff=%v)", deadline.UnixMilli(), deadlineMs, diff)
	}
}

// ---------------------------------------------------------------------------
// Handler: incoming call
// ---------------------------------------------------------------------------
