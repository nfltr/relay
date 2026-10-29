// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testRelay forwards frames between two mock streams the way the relay
// does, optionally rewriting each one (an active relay), and records what
// each side sent.
type testRelay struct {
	mu      sync.Mutex
	fromA   []*pb.TunnelFrame
	changed chan struct{} // closed and replaced whenever fromA grows
	rewrite func(fromA bool, f *pb.TunnelFrame) *pb.TunnelFrame
	latency time.Duration // each frame's one-way delay, order kept
}

func (r *testRelay) run(ctx context.Context, a, b *mockStream) {
	pump := func(from, to *mockStream, fromA bool) {
		for {
			select {
			case f := <-from.sendCh:
				if fromA {
					r.mu.Lock()
					r.fromA = append(r.fromA, f)
					if r.changed != nil {
						close(r.changed)
						r.changed = nil
					}
					r.mu.Unlock()
				}
				if r.rewrite != nil {
					if f = r.rewrite(fromA, f); f == nil {
						continue
					}
				}
				select {
				case to.recvCh <- f:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
	if r.latency > 0 {
		pump = r.delayed(ctx, pump)
	}
	go pump(a, b, true)
	go pump(b, a, false)
}

// delayed puts a one-way delay between from and pump: each frame is handed
// on r.latency after it was sent, in order.
func (r *testRelay) delayed(ctx context.Context, pump func(from, to *mockStream, fromA bool)) func(from, to *mockStream, fromA bool) {
	return func(from, to *mockStream, fromA bool) {
		type timed struct {
			f  *pb.TunnelFrame
			at time.Time
		}
		q := make(chan timed, 1024)
		go func() {
			for {
				select {
				case f := <-from.sendCh:
					q <- timed{f, time.Now().Add(r.latency)}
				case <-ctx.Done():
					return
				}
			}
		}()
		mid := &mockStream{sendCh: make(chan *pb.TunnelFrame), recvCh: from.recvCh}
		go func() {
			for {
				select {
				case tf := <-q:
					time.Sleep(time.Until(tf.at))
					select {
					case mid.sendCh <- tf.f:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		pump(mid, to, fromA)
	}
}

func (r *testRelay) sentByA() []*pb.TunnelFrame {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*pb.TunnelFrame(nil), r.fromA...)
}

// awaitSentByA returns what the caller sent once the relay has recorded n
// frames. The relay records a frame when it takes it off the caller's
// stream, which can follow the call's return (a call returns on the reply,
// not on its own trailing frames), so a count read straight after the call
// can be short.
func (r *testRelay) awaitSentByA(ctx context.Context, t testing.TB, n int) []*pb.TunnelFrame {
	t.Helper()
	for {
		r.mu.Lock()
		if len(r.fromA) >= n {
			r.mu.Unlock()
			return r.sentByA()
		}
		if r.changed == nil {
			r.changed = make(chan struct{})
		}
		ch := r.changed
		r.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatalf("the relay recorded %d of the caller's frames, want %d: %v", len(r.sentByA()), n, ctx.Err())
		}
	}
}

// echoPair connects caller → relay → target, where target echoes and counts
// the request payloads its handler received.
func echoPair(t *testing.T, ctx context.Context, caller, target func(AgentTunnel) *Agent, relay *testRelay) (*Agent, *Agent, *atomic.Int32) {
	t.Helper()
	msA, msB := newMockStream(ctx), newMockStream(ctx)
	a, b := caller(msA), target(msB)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	var ran atomic.Int32
	b.Handle(func(s ServerStream) error {
		data, err := s.Recv()
		if err != nil {
			return err
		}
		ran.Add(1)
		return s.Send(append([]byte("echo:"), data...))
	})
	relay.run(ctx, msA, msB)
	return a, b, &ran
}

func plainAgent(id string) func(AgentTunnel) *Agent {
	return func(s AgentTunnel) *Agent { return NewAgent(id, s) }
}

func e2eeAgent(id string, relayRequests bool) func(AgentTunnel) *Agent {
	return func(s AgentTunnel) *Agent {
		a := NewAgent(id, s)
		a.EnableA2AE2EE()
		a.a2aRelayRequests.Store(relayRequests)
		return a
	}
}

func TestE2EEAgentRefusesPlaintextCaller(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	caller, _, ran := echoPair(t, ctx, plainAgent("old-cli"), e2eeAgent("node-1", false), &testRelay{})

	_, err := caller.Invoke(ctx, "node-1", []byte("launch an agent"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--e2ee") || !strings.Contains(err.Error(), "old-cli sent plaintext") {
		t.Fatalf("plaintext call to an E2EE agent: err = %v, want FailedPrecondition naming --e2ee", err)
	}
	if ran.Load() != 0 {
		t.Fatal("the E2EE agent ran a plaintext request")
	}
}

// The other direction: an E2EE caller never falls back to plaintext when the
// target cannot encrypt; no request payload leaves it in the clear.
func TestE2EECallerNeverFallsBackToPlaintext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relay := &testRelay{}
	caller, _, ran := echoPair(t, ctx, e2eeAgent("hub", false), plainAgent("old-node"), relay)

	_, err := caller.Invoke(ctx, "old-node", []byte("SECRET-BRIEF"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "does not support A2A E2EE") {
		t.Fatalf("E2EE call to a plaintext agent: err = %v", err)
	}
	if ran.Load() != 0 {
		t.Fatal("the plaintext agent ran the request")
	}
	for _, f := range relay.sentByA() {
		if bytes.Contains(f.GetPayload(), []byte("SECRET-BRIEF")) {
			t.Fatalf("E2EE caller sent the brief in plaintext: %v", f)
		}
	}
}

func TestE2EEAgentsStillTalk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	caller, _, _ := echoPair(t, ctx, e2eeAgent("hub", false), e2eeAgent("node-1", false), &testRelay{})
	got, err := caller.Invoke(ctx, "node-1", []byte("hi"))
	if err != nil || string(got) != "echo:hi" {
		t.Fatalf("E2EE ↔ E2EE = %q, %v", got, err)
	}
}

// Relay-originated requests (relay-owned dispatch, fleet-invoke) are served
// only by agents that opted in; everyone else refuses them like any other
// plaintext request, so the relay cannot start work on a node or a hub by
// claiming to be its own agent.
func TestE2EERelayOriginatedRequestsNeedOptIn(t *testing.T) {
	for _, tc := range []struct {
		name          string
		source, mtype string
	}{
		{"relay-owned dispatch", RelayAgentID, "a2a-request"},
		{"fleet invoke", "worker-1", fleetInvokeMessageType},
	} {
		for _, optIn := range []bool{true, false} {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			ms := newMockStream(ctx)
			worker := e2eeAgent("worker-1", optIn)(ms)
			var ran atomic.Int32
			worker.Handle(func(s ServerStream) error { ran.Add(1); _, _ = s.Recv(); return s.Send([]byte("ok")) })
			ms.recvCh <- &pb.TunnelFrame{TransactionId: "txn-" + tc.name, MessageType: tc.mtype, Payload: []byte("task"), Eom: true,
				Routing: &pb.RoutingInfo{AgentId: tc.source, TargetAgentId: "worker-1"}}
			reply := <-ms.sendCh
			if optIn && (ran.Load() != 1 || reply.GetMessageType() == "error") {
				t.Fatalf("%s with opt-in: ran=%d reply=%v", tc.name, ran.Load(), reply)
			}
			if !optIn && (ran.Load() != 0 || reply.GetMessageType() != "error" || codes.Code(reply.GetStatusCode()) != codes.FailedPrecondition) {
				t.Fatalf("%s without opt-in: ran=%d reply=%v", tc.name, ran.Load(), reply)
			}
			_ = worker.Close()
			cancel()
		}
	}
}

// A stream to the relay's own agent ends at the relay: it is not encrypted.
func TestE2EEStreamToRelayAgentIsPlaintext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a := e2eeAgent("worker-1", true)(newMockStream(ctx))
	defer a.Close() //nolint:errcheck
	for target, wantE2EE := range map[string]bool{RelayAgentID: false, "hub": true} {
		s, err := a.NewStream(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.(*clientStream).e2ee != nil; got != wantE2EE {
			t.Fatalf("stream to %s encrypted = %v, want %v", target, got, wantE2EE)
		}
	}
}

// A stray response or error for an unknown transaction (a refused call's
// later frames) is dropped, never run as a request.
func TestStrayResponseFramesAreNotRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ms := newMockStream(ctx)
	a := NewAgent("old-cli", ms)
	defer a.Close() //nolint:errcheck
	var ran atomic.Int32
	a.Handle(func(ServerStream) error { ran.Add(1); return nil })
	for _, mt := range []string{"error", "a2a-response", "a2a-status"} {
		ms.recvCh <- &pb.TunnelFrame{TransactionId: "gone-" + mt, MessageType: mt, Payload: []byte("x"), Routing: &pb.RoutingInfo{AgentId: "node-1"}}
	}
	time.Sleep(100 * time.Millisecond)
	if ran.Load() != 0 {
		t.Fatalf("stray frames ran the handler %d times", ran.Load())
	}
}
