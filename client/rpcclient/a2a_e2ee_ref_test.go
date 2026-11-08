// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/wire/agentwire"
	grpcmd "google.golang.org/grpc/metadata"
)

// refAgent is a keyed agent registered as service id whose relay told it
// the ref ref (the relay's AgentRefKey header on Dial).
func refAgent(id, ref string, kr A2AE2EEKeyring) func(AgentTunnel) *Agent {
	return func(s AgentTunnel) *Agent {
		a := NewAgent(id, s, func(o *agentOptions) { o.ref = ref })
		if err := a.EnableA2AE2EE(kr); err != nil {
			panic(err)
		}
		return a
	}
}

// The callee is the agent's own ref exactly: "<machine id>-<service>" as
// the relay told it, never its bare service, never a dotted scope form.
// The caller, a root holder, seals under m1's key id for any callee,
// so only the callee check refuses.
func TestA2AE2EECalleeIsOwnRef(t *testing.T) {
	store := newTestStore(t, "m1", "m2")
	for _, tc := range []struct {
		callee string
		ok     bool
	}{
		{"m1-node-m1", true},
		{"node-m1", false},      // the bare service
		{"x.node-m1", false},    // the old "<scope>.<name>" form
		{"x.m1-node-m1", false}, // a scope before the ref
	} {
		t.Run(tc.callee, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			caller, rec := hostilePair(t, ctx, keyedAgent("hub", testRootOf{store.machine("m1").(testMachine)}), refAgent("node-m1", "m1-node-m1", store.machine("m1")), nil)
			got, err := caller.Invoke(ctx, tc.callee, []byte("x"))
			if tc.ok && (err != nil || string(got) != "echo:x") {
				t.Fatalf("a call to %s: %q, %v", tc.callee, got, err)
			}
			if !tc.ok && (err == nil || len(rec.requests()) != 0) {
				t.Fatalf("a call to %s was served by m1-node-m1: %q, %v", tc.callee, got, err)
			}
		})
	}
}

// A call for m1-node-m1 rerouted to m2's agent of the same service is
// refused, also when the relay tells m2's agent it is m1-node-m1: m2 holds
// no key of m1, so the handshake fails (spec/proverif a2a_machine.pv, the
// callee's ref from the attacker).
func TestA2AE2EERerouteRefusedWhatEverTheRelayTells(t *testing.T) {
	store := newTestStore(t, "m1", "m2")
	for _, told := range []string{"m2-node-m1", "m1-node-m1"} {
		t.Run(told, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			caller, rec := hostilePair(t, ctx, keyedAgent("hub", store), refAgent("node-m1", told, store.machine("m2")), nil)
			if got, err := caller.Invoke(ctx, "m1-node-m1", []byte("SECRET-FOR-M1")); err == nil || len(rec.requests()) != 0 {
				t.Fatalf("a call to m1-node-m1 rerouted to m2 (told %s) was served: %q, %v", told, got, err)
			}
		})
	}
}

// A machine's agent calls under its ref: a root holder finds the caller's
// machine key by the caller field, so the bare service would not do.
func TestA2AE2EECallerIsOwnRef(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	caller, _ := hostilePair(t, ctx, refAgent("node-m1", "m1-node-m1", store.machine("m1")), keyedAgent("hub", store), nil)
	if got, err := caller.Invoke(ctx, "hub", []byte("x")); err != nil || string(got) != "echo:x" {
		t.Fatalf("m1-node-m1 calling hub: %q, %v", got, err)
	}
}

// Dial takes its ref from the relay's accept headers; a relay that states
// none leaves the agent id.
func TestDialTakesTheRelaysRef(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, tc := range []struct{ told, want string }{{"m1-node-m1", "m1-node-m1"}, {"", "node-m1"}} {
		r := &registeringRelay{header: grpcmd.MD{}}
		if tc.told != "" {
			r.header.Set(agentwire.AgentRefKey, tc.told)
		}
		a, err := Dial(ctx, serveRelay(t, r), WithAgentID("node-m1"), WithAPIKey("k"), WithTLS(false))
		if err != nil {
			t.Fatal(err)
		}
		if got := a.Ref(); got != tc.want {
			t.Fatalf("told %q: Ref() = %q, want %q", tc.told, got, tc.want)
		}
		_ = a.Close()
	}
}

// A machine's call to a root holder, delivered to an agent of the same
// machine (a sibling, or the caller itself) that the relay told "you are
// the root holder", is refused: the init states the initiator's role in
// its prologue and a machine answers root holders only (a2a_machine.pv
// queries 7 and 16, mutant drop-role).
func TestA2AE2EEMachineInitNotAnsweredByAMachine(t *testing.T) {
	store := newTestStore(t, "m1")
	t.Run("sibling", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		caller, rec := hostilePair(t, ctx, refAgent("worker-m1", "m1-worker-m1", store.machine("m1")), refAgent("node-m1", "r1-hub", store.machine("m1")), nil)
		if got, err := caller.Invoke(ctx, "r1-hub", []byte("FOR-THE-HUB")); err == nil || len(rec.requests()) != 0 {
			t.Fatalf("m1-worker-m1's call to the hub was served by its sibling: %q, %v", got, err)
		}
	})
	t.Run("itself", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ms := newMockStream(ctx)
		a := refAgent("worker-m1", "r1-hub", store.machine("m1"))(ms)
		defer a.Close() //nolint:errcheck
		ran := make(chan struct{}, 1)
		a.Handle(func(ServerStream) error { ran <- struct{}{}; return nil })
		go func() { // the relay returns every frame to its sender
			for {
				select {
				case f := <-ms.sendCh:
					ms.recvCh <- f
				case <-ctx.Done():
					return
				}
			}
		}()
		if got, err := a.Invoke(ctx, "r1-hub", []byte("FOR-THE-HUB")); err == nil {
			t.Fatalf("a reflected call was answered: %q", got)
		}
		select {
		case <-ran:
			t.Fatal("the reflected call ran the handler")
		default:
		}
	})
}
