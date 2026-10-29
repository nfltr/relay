// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Drain returns once the relay acknowledged and every call already
// delivered is answered; against a relay that never acknowledges (one that
// predates the handshake) it returns at its bound.
func TestAgentDrainWaitsForTheAckThenForDeliveredCalls(t *testing.T) {
	ctx := t.Context()
	stream := newMockStream(ctx)
	agent := NewAgent("leaving", stream)
	defer agent.Close() //nolint:errcheck
	release := make(chan struct{})
	agent.Handle(func(ServerStream) error { <-release; return nil })
	stream.recvCh <- &pb.TunnelFrame{MessageType: "a2a-request", TransactionId: "delivered", Payload: []byte("x"), Eom: true,
		Routing: &pb.RoutingInfo{AgentId: "hub"}}
	for !agent.hasIncomingCalls() {
		time.Sleep(time.Millisecond)
	}

	done := make(chan error, 1)
	go func() { done <- agent.Drain(ctx) }()
	var drainFrame *pb.TunnelFrame
	for drainFrame == nil {
		if f := <-stream.sendCh; f.GetMessageType() == AgentDrainMessageType {
			drainFrame = f
		}
	}
	stream.recvCh <- &pb.TunnelFrame{MessageType: AgentDrainAckMessageType, TransactionId: drainFrame.GetTransactionId(), Eom: true}
	select {
	case err := <-done:
		t.Fatalf("Drain returned %v while a delivered call was unanswered", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Drain = %v, want nil once acknowledged and answered", err)
	}

	bounded, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := agent.Drain(bounded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain without an acknowledgement = %v, want its bound", err)
	}
}

func TestIsAgentDrainingMatchesOnlyTheRelayDrainRefusal(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{status.Error(codes.Unavailable, AgentDrainingDetail), true},
		{status.Error(codes.Unavailable, "target agent disconnected"), false},
		{status.Error(codes.NotFound, AgentDrainingDetail), false},
		{errors.New(AgentDrainingDetail), false},
	} {
		if got := IsAgentDraining(tc.err); got != tc.want {
			t.Errorf("IsAgentDraining(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
