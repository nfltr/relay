// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
)

// waitFrames waits until the agent sent a frame of each of types for txn,
// in any order, skipping others (window updates); 5 s only against a hang.
func waitFrames(t *testing.T, ms *mockStream, txn string, types ...string) {
	t.Helper()
	bound := time.After(5 * time.Second)
	for len(types) > 0 {
		select {
		case f := <-ms.sendCh:
			if f.GetTransactionId() == txn {
				types = slices.DeleteFunc(types, func(typ string) bool { return typ == f.GetMessageType() })
			}
		case <-bound:
			t.Fatalf("no %v frame of %s", types, txn)
		}
	}
}

// waitNoEntry waits until the agent serves no call of txn (handleCall
// deleted its entry after the status trailer).
func waitNoEntry(t *testing.T, a *Agent, txn string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if _, ok := a.incoming.Load(txn); !ok {
			return
		}
	}
	t.Fatalf("the agent still serves %s", txn)
}

// A request frame that reaches the target after the call's handler
// returned is dropped: it never starts a second handler call for the
// transaction (spec/CallLifecycle.tla AtMostOneCall; mutant
// CL:late-new-call is the code before lane CONFORM6-RELAY, where it ran
// the handler again with the call's later requests).
func TestLateRequestFrameStartsNoCall(t *testing.T) {
	ms := newMockStream(t.Context())
	a := NewAgent(testTargetAgentId, ms)
	defer a.Close() //nolint:errcheck
	var calls atomic.Int32
	a.Handle(func(s ServerStream) error {
		calls.Add(1)
		_, err := s.Recv() // the first request, then return: a unary handler
		return err
	})
	frame := func(txn, data string, cont bool) *pb.TunnelFrame {
		return &pb.TunnelFrame{TransactionId: txn, MessageType: "a2a-request", Payload: []byte(data),
			Continuation: cont, Routing: &pb.RoutingInfo{AgentId: "agent-a"}}
	}

	ms.recvCh <- frame("txn", "first", false)
	waitFrames(t, ms, "txn", "a2a-status")
	waitNoEntry(t, a, "txn")
	ms.recvCh <- frame("txn", "second", true) // sent before the caller saw the status
	ms.recvCh <- frame("other", "first", false)
	waitFrames(t, ms, "other", "a2a-status") // the receive loop took "second" before it
	if n := calls.Load(); n != 2 {
		t.Fatalf("%d handler calls for two calls, want 2: a late frame of an ended call started one", n)
	}
}

// The target keeps nothing for a call that ended, however it ended
// (spec/CallLifecycle.tla NoEndedEntry): after calls whose handlers
// returned, calls refused for breaking their credit and calls whose
// frames came late, it serves no call.
func TestEndedAndRefusedCallsLeaveNoEntry(t *testing.T) {
	ms := newMockStream(t.Context())
	a := NewAgent(testTargetAgentId, ms)
	defer a.Close() //nolint:errcheck
	a.Handle(func(s ServerStream) error {
		if _, err := s.Recv(); err != nil {
			return err
		}
		<-s.Context().Done() // until the call is refused, cancelled or ends
		return nil
	})
	const n = 20
	for i := range n {
		txn := "txn-" + string(rune('a'+i))
		ms.recvCh <- &pb.TunnelFrame{TransactionId: txn, MessageType: "a2a-request", Payload: []byte("x"),
			Routing: &pb.RoutingInfo{AgentId: "agent-a"}}
		switch i % 2 {
		case 0: // refused: its caller grants past the response window
			ms.recvCh <- windowFrame(txn, ResponseWindow)
			waitFrames(t, ms, txn, "error", "a2a-status")
		default: // cancelled by its caller
			ms.recvCh <- &pb.TunnelFrame{TransactionId: txn, MessageType: "cancel", Eom: true}
			waitFrames(t, ms, txn, "a2a-status")
		}
		ms.recvCh <- &pb.TunnelFrame{TransactionId: txn, MessageType: "a2a-request", Payload: []byte("late"),
			Continuation: true, Routing: &pb.RoutingInfo{AgentId: "agent-a"}}
		ms.recvCh <- &pb.TunnelFrame{TransactionId: txn, MessageType: "a2a-request", Eom: true,
			Continuation: true, Routing: &pb.RoutingInfo{AgentId: "agent-a"}}
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		entries := 0
		a.incoming.Range(func(any, any) bool { entries++; return true })
		if entries == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d entries after %d ended calls, want 0", entries, n)
		}
	}
}

// A call's first frame always fits: a fresh call's credit (RequestWindow)
// and buffer take it. So the target never refuses a call at its first
// frame, and keeps no entry for one (the refusal branch the code had there
// is gone; spec/CallLifecycle.tla mutant CL:refused-first-kept).
func TestFirstFrameFitsAFreshCall(t *testing.T) {
	a := NewAgent(testTargetAgentId, newMockStream(t.Context()))
	defer a.Close() //nolint:errcheck
	msg := &pb.TunnelFrame{TransactionId: "txn", Payload: []byte("x"), Routing: &pb.RoutingInfo{AgentId: "agent-a"}}
	ss := a.newServerStream(msg, nil, nil)
	defer ss.end()
	if err := ss.pushRequest(msg); err != nil {
		t.Fatalf("a fresh call's first frame: %v", err)
	}
}

// The caller marks every request data frame after the call's first as a
// continuation (TunnelFrame.continuation), so its target can tell a late
// frame from a call's start.
func TestCallerMarksContinuationFrames(t *testing.T) {
	ms := newMockStream(t.Context())
	a := NewAgent("agent-a", ms)
	defer a.Close() //nolint:errcheck
	cs, err := a.NewStream(t.Context(), testTargetAgentId)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := cs.Send([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		f := <-ms.sendCh
		if f.GetContinuation() != (i > 0) {
			t.Fatalf("request frame %d: continuation %v, want %v", i, f.GetContinuation(), i > 0)
		}
	}
	if f := <-ms.sendCh; !f.GetEom() {
		t.Fatalf("frame after the requests: %v, want the request's end", f)
	}
}
