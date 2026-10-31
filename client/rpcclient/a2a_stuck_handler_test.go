// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"io"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
)

// TestStuckHandlerDoesNotHoldTheReceiveLoop guards the agent-to-agent
// sibling of the stuck-client rule: a
// handler that takes none of its call's frames must not stop the tunnel's
// receive loop, which serves every call and response of the agent. Past
// its call's 16-frame buffer the loop waits for it at most consumerStall;
// then the call is refused (ResourceExhausted to its caller) and the
// agent's other calls go on.
func TestStuckHandlerDoesNotHoldTheReceiveLoop(t *testing.T) {
	defer func(d time.Duration) { consumerStall = d }(consumerStall)
	consumerStall = 300 * time.Millisecond
	ms := newMockStream(t.Context())
	agent := NewAgent(testTargetAgentId, ms)
	defer agent.Close() //nolint:errcheck
	agent.Handle(func(stream ServerStream) error {
		if stream.SourceAgentID() == "stuck" {
			<-stream.Context().Done() // takes none of its frames
			return stream.Context().Err()
		}
		_, _ = io.ReadAll(recvReader{stream})
		return stream.Send([]byte("ok"))
	})
	go func() {
		for range 40 { // past the call's buffer and the stream's
			ms.recvCh <- &pb.TunnelFrame{Payload: []byte("x"), MessageType: "a2a-request", TransactionId: "stuck",
				Routing: &pb.RoutingInfo{AgentId: "stuck", TargetAgentId: testTargetAgentId}}
		}
		ms.recvCh <- &pb.TunnelFrame{Payload: []byte("hi"), MessageType: "a2a-request", TransactionId: "other", Eom: true,
			Routing: &pb.RoutingInfo{AgentId: "agent-a", TargetAgentId: testTargetAgentId}}
	}()
	var refused, answered bool
	deadline := time.After(10 * time.Second)
	for !refused || !answered {
		select {
		case f := <-ms.sendCh:
			switch {
			case f.GetTransactionId() == "stuck" && f.GetMessageType() == "error" && codes.Code(f.GetStatusCode()) == codes.ResourceExhausted:
				refused = true
			case f.GetTransactionId() == "other" && string(f.GetPayload()) == "ok":
				answered = true
			}
		case <-deadline:
			t.Fatalf("refused the stuck call %v, answered the other %v: the receive loop waits on a stuck handler", refused, answered)
		}
	}
}

// recvReader reads a ServerStream's request messages as one stream.
type recvReader struct{ s ServerStream }

func (r recvReader) Read(b []byte) (int, error) {
	data, err := r.s.Recv()
	return copy(b, data), err
}
