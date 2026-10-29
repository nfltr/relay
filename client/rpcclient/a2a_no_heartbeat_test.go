// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
)

// heartbeatLoopRunning reports whether a's heartbeatLoop goroutine exists:
// a goroutine dump names the receiver of each frame.
func heartbeatLoopRunning(a *Agent) bool {
	buf := make([]byte, 1<<22)
	dump := string(buf[:runtime.Stack(buf, true)])
	return strings.Contains(dump, fmt.Sprintf(".(*Agent).heartbeatLoop(%p", a))
}

// TestWithoutHeartbeat_NoLoopStillServes: an agent made WithoutHeartbeat
// runs no heartbeatLoop goroutine (one made without it does) and still
// serves a stream.
func TestWithoutHeartbeat_NoLoopStillServes(t *testing.T) {
	ctx := t.Context()
	with := NewAgent("with-heartbeat", newMockStream(ctx))
	defer with.Close() //nolint:errcheck
	ms := newMockStream(ctx)
	agent := NewAgent("no-heartbeat", ms, WithoutHeartbeat())
	defer agent.Close() //nolint:errcheck

	deadline := time.Now().Add(2 * time.Second)
	for !heartbeatLoopRunning(with) {
		if time.Now().After(deadline) {
			t.Fatal("control agent's heartbeatLoop not found in the goroutine dump")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if heartbeatLoopRunning(agent) {
		t.Fatal("agent WithoutHeartbeat runs a heartbeatLoop")
	}

	agent.Handle(func(stream ServerStream) error {
		data, err := stream.Recv()
		if err != nil {
			return err
		}
		return stream.Send([]byte("echo:" + string(data)))
	})
	ms.recvCh <- &pb.TunnelFrame{
		Payload:       []byte("ping"),
		MessageType:   "a2a-request",
		TransactionId: "txn-1",
		Routing:       &pb.RoutingInfo{AgentId: "caller", TargetAgentId: "no-heartbeat"},
		Eom:           true,
	}
	select {
	case f := <-ms.sendCh:
		if string(f.GetPayload()) != "echo:ping" {
			t.Fatalf("response payload = %q, want echo:ping", f.GetPayload())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no response from agent WithoutHeartbeat")
	}
}
