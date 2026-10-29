// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHandle_IncomingCall(t *testing.T) {
	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent(testTargetAgentId, ms)
	defer agent.Close() //nolint:errcheck

	handlerDone := make(chan struct{})
	var handlerSource string
	var handlerData []string

	agent.Handle(func(stream ServerStream) error {
		defer close(handlerDone)
		handlerSource = stream.SourceAgentID()
		for {
			data, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			handlerData = append(handlerData, string(data))
		}
		stream.SetHeader(MD{"x-handler": "v1"})
		if err := stream.Send([]byte("resp1")); err != nil {
			return err
		}
		return nil
	})

	txnID := "incoming-txn-1"

	// Feed 2 request messages + EOM marker.
	ms.recvCh <- &pb.TunnelFrame{
		Payload:       []byte("req1"),
		MessageType:   "a2a-request",
		TransactionId: txnID,
		Routing:       &pb.RoutingInfo{AgentId: "agent-a", TargetAgentId: testTargetAgentId},
	}
	ms.recvCh <- &pb.TunnelFrame{
		Payload:       []byte("req2"),
		MessageType:   "a2a-request",
		TransactionId: txnID,
		Routing:       &pb.RoutingInfo{AgentId: "agent-a", TargetAgentId: testTargetAgentId},
		Eom:           true,
	}

	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not complete")
	}

	if handlerSource != "agent-a" {
		t.Fatalf("expected source=agent-a, got %s", handlerSource)
	}
	if len(handlerData) != 2 || handlerData[0] != "req1" || handlerData[1] != "req2" {
		t.Fatalf("unexpected handler data: %v", handlerData)
	}

	// Verify outgoing response + status trailer.
	var sent []*pb.TunnelFrame
	timeout := time.After(2 * time.Second)
	for range 2 {
		select {
		case msg := <-ms.sendCh:
			sent = append(sent, msg)
		case <-timeout:
			t.Fatalf("timeout waiting for sent messages (got %d)", len(sent))
		}
	}

	// First: resp1 (Eom=false).
	if string(sent[0].GetPayload()) != "resp1" {
		t.Fatalf("expected resp1, got %q", sent[0].GetPayload())
	}
	if sent[0].GetRouting().GetInitialMetadata()["x-handler"] != "v1" {
		t.Fatal("expected initial_metadata x-handler=v1")
	}

	// Second: status trailer (Eom=true, StatusCode=0).
	if !sent[1].GetEom() {
		t.Fatal("expected EOM on status trailer")
	}
	if sent[1].GetStatusCode() != 0 {
		t.Fatalf("expected status_code=0, got %d", sent[1].GetStatusCode())
	}
}

// ---------------------------------------------------------------------------
// Handler: error status propagation
// ---------------------------------------------------------------------------

func TestHandle_ErrorStatus(t *testing.T) {
	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent(testTargetAgentId, ms)
	defer agent.Close() //nolint:errcheck

	handlerDone := make(chan struct{})
	agent.Handle(func(stream ServerStream) error {
		defer close(handlerDone)
		_, _ = stream.Recv() // consume request
		return status.Errorf(codes.InvalidArgument, "bad request")
	})

	ms.recvCh <- &pb.TunnelFrame{
		Payload:       []byte("bad"),
		MessageType:   "a2a-request",
		TransactionId: "err-txn-1",
		Routing:       &pb.RoutingInfo{AgentId: "agent-a", TargetAgentId: testTargetAgentId},
		Eom:           true,
	}

	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not complete")
	}

	// Verify the status trailer.
	select {
	case msg := <-ms.sendCh:
		if !msg.GetEom() {
			t.Fatal("expected EOM")
		}
		if codes.Code(msg.GetStatusCode()) != codes.InvalidArgument {
			t.Fatalf("expected InvalidArgument, got %d", msg.GetStatusCode())
		}
		if msg.GetStatusDetail() != "bad request" {
			t.Fatalf("expected 'bad request', got %q", msg.GetStatusDetail())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for status trailer")
	}
}

// ---------------------------------------------------------------------------
// Cancel: source sends cancel message
// ---------------------------------------------------------------------------

func TestHandle_CancelPropagation(t *testing.T) {
	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent(testTargetAgentId, ms)
	defer agent.Close() //nolint:errcheck

	handlerCtxDone := make(chan struct{})
	agent.Handle(func(stream ServerStream) error {
		defer close(handlerCtxDone)
		<-stream.Context().Done()
		return stream.Context().Err()
	})

	txnID := "cancel-txn-1"
	ms.recvCh <- &pb.TunnelFrame{
		Payload:       []byte("data"),
		MessageType:   "a2a-request",
		TransactionId: txnID,
		Routing:       &pb.RoutingInfo{AgentId: "agent-a", TargetAgentId: testTargetAgentId},
	}

	// Give handler time to start.
	time.Sleep(50 * time.Millisecond)

	// Send cancel.
	ms.recvCh <- &pb.TunnelFrame{
		MessageType:   "cancel",
		TransactionId: txnID,
		Routing:       &pb.RoutingInfo{AgentId: "agent-a", TargetAgentId: testTargetAgentId},
	}

	select {
	case <-handlerCtxDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handler context was not cancelled")
	}
}

func TestAgent_SendsHeartbeats(t *testing.T) {
	ctx := t.Context()

	originalInterval := agentHeartbeatInterval
	agentHeartbeatInterval = 10 * time.Millisecond
	defer func() { agentHeartbeatInterval = originalInterval }()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	deadline := time.After(250 * time.Millisecond)
	for {
		select {
		case msg := <-ms.sendCh:
			if msg.GetTransactionId() == "" && len(msg.GetPayload()) == 0 && !msg.GetEom() {
				return
			}
		case <-deadline:
			t.Fatal("expected heartbeat frame")
		}
	}
}

// TestAgent_SuppressesHeartbeatWhileDataFlowing verifies that heartbeats are
// NOT emitted while data frames are actively being sent on the stream. The
// data frame itself serves as proof-of-life to the server (the relay resets
// its recvThreshold ticker on any incoming message, heartbeat or data), so an
// additional empty heartbeat is redundant and — worse — can stall sendLoop
// behind a slow large-payload Send under cursor-mcp-style bursty workloads.
// Heartbeats resume immediately once the stream goes idle.
func TestAgent_SuppressesHeartbeatWhileDataFlowing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	originalInterval := agentHeartbeatInterval
	agentHeartbeatInterval = 10 * time.Millisecond
	defer func() { agentHeartbeatInterval = originalInterval }()

	ms := newSlowSendStream(ctx, 5*time.Millisecond)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	stream, err := agent.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream error: %v", err)
	}
	for i := range 64 {
		if err := stream.Send([]byte("x")); err != nil {
			t.Fatalf("Send(%d) error: %v", i, err)
		}
	}

	// While the 64-frame backlog drains (each frame takes 5ms ≈ 320ms total),
	// no empty heartbeat frames should appear — data alone is proof-of-life.
	deadline := time.After(600 * time.Millisecond)
	dataFrames := 0
	heartbeatFrames := 0
	for dataFrames < 64 {
		select {
		case msg := <-ms.sentCh:
			if msg.GetTransactionId() == "" && len(msg.GetPayload()) == 0 && !msg.GetEom() {
				heartbeatFrames++
			} else {
				dataFrames++
			}
		case <-deadline:
			t.Fatalf("backlog did not drain in time: data=%d heartbeats=%d", dataFrames, heartbeatFrames)
		}
	}
	if heartbeatFrames != 0 {
		t.Fatalf("expected zero heartbeats while data was flowing, got %d", heartbeatFrames)
	}

	// Stream is now idle. A heartbeat should arrive within ~2 intervals.
	idleDeadline := time.After(100 * time.Millisecond)
	for {
		select {
		case msg := <-ms.sentCh:
			if msg.GetTransactionId() == "" && len(msg.GetPayload()) == 0 && !msg.GetEom() {
				return
			}
		case <-idleDeadline:
			t.Fatalf("expected heartbeat to resume after stream went idle")
		}
	}
}

func TestAgent_DoesNotQueueHeartbeatBehindInFlightData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	originalInterval := agentHeartbeatInterval
	agentHeartbeatInterval = 10 * time.Millisecond
	defer func() { agentHeartbeatInterval = originalInterval }()

	ms := newGatedSendStream(ctx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck
	defer func() {
		select {
		case <-ms.releaseData:
		default:
			close(ms.releaseData)
		}
	}()

	stream, err := agent.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatalf("NewStream error: %v", err)
	}
	sendDone := make(chan error, 1)
	go func() { sendDone <- stream.Send([]byte("in-flight")) }()

	select {
	case <-ms.dataStarted:
	case <-ctx.Done():
		t.Fatal("data send did not start")
	}
	time.Sleep(4 * agentHeartbeatInterval)
	if queued := len(agent.heartbeatCh); queued != 0 {
		t.Fatalf("heartbeat queued behind an in-flight data frame: %d", queued)
	}

	close(ms.releaseData)
	if err := <-sendDone; err != nil {
		t.Fatalf("Send error: %v", err)
	}
	select {
	case msg := <-ms.sentCh:
		if msg.GetTransactionId() == "" {
			t.Fatal("heartbeat was sent before the in-flight data frame")
		}
	case <-ctx.Done():
		t.Fatal("data frame was not sent")
	}

	for {
		select {
		case msg := <-ms.sentCh:
			if msg.GetTransactionId() == "" && len(msg.GetPayload()) == 0 && !msg.GetEom() {
				return
			}
		case <-ctx.Done():
			t.Fatal("heartbeat did not resume after data became idle")
		}
	}
}

// ---------------------------------------------------------------------------
// Heartbeat filtering
// ---------------------------------------------------------------------------

func TestHeartbeatFiltering(t *testing.T) {
	ctx := t.Context()

	ms := newMockStream(ctx)
	agent := NewAgent("agent-a", ms)
	defer agent.Close() //nolint:errcheck

	// Send heartbeats (empty messages).
	ms.recvCh <- &pb.TunnelFrame{}
	ms.recvCh <- nil

	// Send a real response.
	txnID := "hb-txn-1"
	go func() {
		// Wait for the agent to register the pending call.
		time.Sleep(50 * time.Millisecond)
		ms.recvCh <- &pb.TunnelFrame{
			Payload:       []byte("ok"),
			MessageType:   "a2a-response",
			TransactionId: txnID,
			Eom:           true,
		}
	}()

	// Register a pending call manually.
	cs := &clientStream{
		agent:      agent,
		txnID:      txnID,
		responseCh: make(chan *pb.TunnelFrame, clientStreamResponseBufferSize),
		headerCh:   make(chan struct{}),
		ctx:        ctx,
	}
	agent.pending.Store(txnID, cs)

	select {
	case resp := <-cs.responseCh:
		if string(resp.GetPayload()) != "ok" {
			t.Fatalf("expected 'ok', got %q", resp.GetPayload())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout — heartbeats may have blocked the recv loop")
	}
}
