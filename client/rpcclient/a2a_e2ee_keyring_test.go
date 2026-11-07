// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// Per-machine keys (A2AE2EEKeyring): one test per invariant of nfltr's
// spec/a2akeys/MachineKeys.tla at this layer. PinNeverSilentlyReplaced is
// structural here: A2AE2EEKeyring has no method that writes.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
)

// testStore is a root holder's keyring over a store it changes in place
// (nfltr's is a2akeys.Keyring over a2a-machines.json).
type testStore struct {
	root []byte
	mu   sync.Mutex
	gen  map[string]int
	rev  map[string]bool
}

func newTestStore(t *testing.T, names ...string) *testStore {
	s := &testStore{root: testPairingKey(t, secretA), gen: map[string]int{}, rev: map[string]bool{}}
	for _, n := range names {
		s.gen[n] = 1
	}
	return s
}

func testMachineKey(root []byte, name string, gen int) []byte {
	m := hmac.New(sha256.New, root)
	m.Write([]byte(name + "." + strconv.Itoa(gen)))
	return m.Sum(nil)
}

// machine is name's keyring at its current generation (its key file).
func (s *testStore) machine(name string) A2AE2EEKeyring {
	s.mu.Lock()
	defer s.mu.Unlock()
	return testMachine{id: name + "." + strconv.Itoa(s.gen[name]), key: testMachineKey(s.root, name, s.gen[name])}
}

func (s *testStore) revoke(name string) { s.mu.Lock(); s.rev[name] = true; s.mu.Unlock() }
func (s *testStore) rotate(name string) {
	s.mu.Lock()
	s.gen[name]++
	s.rev[name] = false
	s.mu.Unlock()
}

func (s *testStore) Own() (string, []byte) { return "", s.root }

func (s *testStore) Peer(id string) ([]byte, error) {
	if id == "" {
		return s.root, nil
	}
	name, g, _ := strings.Cut(id, ".")
	gen, _ := strconv.Atoi(g)
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.gen[name]; !ok || cur != gen || s.rev[name] {
		return nil, fmt.Errorf("machine key %s is unknown, revoked or rotated", id)
	}
	return testMachineKey(s.root, name, gen), nil
}

func (s *testStore) Valid(id string) bool { _, err := s.Peer(id); return err == nil }

type testMachine struct {
	id  string
	key []byte
}

func (m testMachine) Own() (string, []byte) { return m.id, m.key }

func (m testMachine) Peer(id string) ([]byte, error) {
	if id != m.id {
		return nil, errors.New("a machine holds its own key only")
	}
	return m.key, nil
}

func (m testMachine) Valid(id string) bool { return id == m.id }

func invokeOK(t *testing.T, caller *Agent, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got, err := caller.Invoke(ctx, target, []byte("hi")); err != nil || string(got) != "echo:hi" {
		t.Fatalf("Invoke %s = %q, %v", target, got, err)
	}
}

func invokeRefused(t *testing.T, caller *Agent, target string, ran interface{ Load() int32 }) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := caller.Invoke(ctx, target, []byte("hi")); !strings.Contains(fmt.Sprint(err), "pairing") && !strings.Contains(fmt.Sprint(err), "key id") {
		t.Fatalf("Invoke %s: err = %v, want a pairing-key refusal", target, err)
	}
	if ran.Load() != 0 {
		t.Fatalf("%s ran a request it should have refused", target)
	}
}

// A root holder and a machine talk both ways, interactive and 0-RTT; the
// root-only pairing key keeps today's wire (vectors unchanged).
func TestA2AE2EEKeyringRootAndMachine(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m1, _, _ := echoPair(t, ctx, keyedAgent("kr-m1", store.machine("m1")), keyedAgent("kr-hub", store), &testRelay{})
	invokeOK(t, m1, "kr-hub")
	relay := &testRelay{}
	hub, node, _ := echoPair(t, ctx, keyedAgent("kr-hub2", store), keyedAgent("kr-node", store.machine("m1")), relay)
	invokeOK(t, hub, "kr-node")
	learn0RTT(t, node, store.machine("m1"))
	invokeOK(t, hub, "kr-node")
	if types := frameTypes(relay.sentByA()); !contains(types, a2aE2EEInit0RTTMessageType) {
		t.Fatalf("root to machine with a learned label took no first flight: %v", types)
	}
}

// AcceptedIsSender: a machine cannot be accepted as another, by naming
// another machine's id (relay relabel, or a forged file) or calling another
// machine directly.
func TestA2AE2EEKeyringNoMachineSpeaksAsAnother(t *testing.T) {
	store := newTestStore(t, "m1", "m2")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	relabel := &testRelay{rewrite: func(fromA bool, f *pb.TunnelFrame) *pb.TunnelFrame {
		if fromA && f.GetMessageType() == a2aE2EEInitMessageType {
			f = cloneFrame(f)
			f.Payload = append(f.GetPayload()[:a2aE2EEPubLen+a2aE2EEPairingTagLen:a2aE2EEPubLen+a2aE2EEPairingTagLen], "m2.1"...)
		}
		return f
	}}
	caller, _, ran := echoPair(t, ctx, keyedAgent("as-m1", store.machine("m1")), keyedAgent("as-hub", store), relabel)
	invokeRefused(t, caller, "as-hub", ran)
	m1 := store.machine("m1").(testMachine)
	forged, _, ran := echoPair(t, ctx, keyedAgent("as-forged", testMachine{id: "m2.1", key: m1.key}), keyedAgent("as-hub2", store), &testRelay{})
	invokeRefused(t, forged, "as-hub2", ran)
	peer, _, ran := echoPair(t, ctx, keyedAgent("as-m1b", m1), keyedAgent("as-m2", store.machine("m2")), &testRelay{})
	invokeRefused(t, peer, "as-m2", ran)
}

// NoMessageFromRevokedMachine and OtherMachinesUnaffected: after revoking
// m1 its handshakes are refused both ways (0-RTT label included) while m2
// is served; rotating m1 refuses its old file and admits the new one.
func TestA2AE2EEKeyringRevokeRefusesOnlyThatMachine(t *testing.T) {
	store := newTestStore(t, "m1", "m2")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	oldM1 := store.machine("m1")
	m1, _, m1Ran := echoPair(t, ctx, keyedAgent("rv-m1", oldM1), keyedAgent("rv-hub1", store), &testRelay{})
	m2, _, _ := echoPair(t, ctx, keyedAgent("rv-m2", store.machine("m2")), keyedAgent("rv-hub2", store), &testRelay{})
	hub1, node1, node1Ran := echoPair(t, ctx, keyedAgent("rv-hub3", store), keyedAgent("rv-node1", oldM1), &testRelay{})
	hub2, _, _ := echoPair(t, ctx, keyedAgent("rv-hub4", store), keyedAgent("rv-node2", store.machine("m2")), &testRelay{})
	invokeOK(t, m1, "rv-hub1")
	invokeOK(t, hub1, "rv-node1")

	store.revoke("m1")
	m1Ran.Store(0)
	node1Ran.Store(0)
	invokeRefused(t, m1, "rv-hub1", m1Ran)
	invokeRefused(t, hub1, "rv-node1", node1Ran)
	learn0RTT(t, node1, oldM1)
	invokeRefused(t, hub1, "rv-node1", node1Ran)
	invokeOK(t, m2, "rv-hub2")
	invokeOK(t, hub2, "rv-node2")

	store.rotate("m1")
	invokeRefused(t, m1, "rv-hub1", m1Ran)
	m1New, _, _ := echoPair(t, ctx, keyedAgent("rv-m1-new", store.machine("m1")), keyedAgent("rv-hub5", store), &testRelay{})
	invokeOK(t, m1New, "rv-hub5")
	invokeOK(t, m2, "rv-hub2")
}

// NoMessageFromRevokedMachine for frames: a revoke ends calls in flight at
// their next frame, both directions (machine calling the root, root calling
// the machine), and a call of another machine goes on.
func TestA2AE2EEKeyringRevokeEndsCallsInFlight(t *testing.T) {
	store := newTestStore(t, "m1", "m2")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type call struct {
		cs      ClientStream
		handled chan error
	}
	open := func(callerKR, targetKR A2AE2EEKeyring, callerID, targetID string) call {
		msA, msB := newMockStream(ctx), newMockStream(ctx)
		a, b := keyedAgent(callerID, callerKR)(msA), keyedAgent(targetID, targetKR)(msB)
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		handled := make(chan error, 1)
		b.Handle(func(s ServerStream) error {
			for {
				data, err := s.Recv()
				if err == io.EOF {
					handled <- nil
					return nil
				}
				if err == nil {
					err = s.Send(append([]byte("echo:"), data...))
				}
				if err != nil {
					handled <- err
					return err
				}
			}
		})
		(&testRelay{}).run(ctx, msA, msB)
		cs, err := a.NewStream(ctx, targetID)
		if err != nil {
			t.Fatal(err)
		}
		return call{cs, handled}
	}
	roundTrip := func(c call) error {
		if err := c.cs.Send([]byte("hi")); err != nil {
			return err
		}
		r, err := c.cs.Recv()
		if err == nil && string(r.Data) != "echo:hi" {
			err = fmt.Errorf("got %q", r.Data)
		}
		return err
	}
	toRoot := open(store.machine("m1"), store, "fl-m1", "fl-hub")
	fromRoot := open(store, store.machine("m1"), "fl-hub2", "fl-node1")
	other := open(store.machine("m2"), store, "fl-m2", "fl-hub3")
	for _, c := range []call{toRoot, fromRoot, other} {
		if err := roundTrip(c); err != nil {
			t.Fatalf("before the revoke: %v", err)
		}
	}

	store.revoke("m1")
	// m1 calling the root: its next frame is refused at the root, whose
	// handler's Recv fails, and the call ends with that refusal.
	if err := roundTrip(toRoot); err == nil || !strings.Contains(err.Error(), "revoked or rotated") {
		t.Fatalf("m1's frame after the revoke: err = %v, want the revoke", err)
	}
	if err := <-toRoot.handled; err == nil || !strings.Contains(err.Error(), "revoked or rotated") {
		t.Fatalf("root's handler after the revoke: %v", err)
	}
	// The root calling m1: the root seals nothing more under m1's key.
	if err := fromRoot.cs.Send([]byte("hi")); err == nil || !strings.Contains(err.Error(), "revoked or rotated") {
		t.Fatalf("root's frame to m1 after the revoke: err = %v", err)
	}
	if err := roundTrip(other); err != nil {
		t.Fatalf("m2's call after m1's revoke: %v", err)
	}
}

func learn0RTT(t *testing.T, target *Agent, kr A2AE2EEKeyring) {
	t.Helper()
	LearnA2AE2EEPeer(target.agentID, map[string]string{A2AE2EEStaticLabel: target.e2eeStatic().label(target.agentID, kr)})
	t.Cleanup(func() { LearnA2AE2EEPeer(target.agentID, nil) })
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// The keyed handshake payload is pub ‖ tag ‖ key id: a root-key id ("")
// adds nothing (today's 64 bytes), an id longer than a2aE2EEKeyIDMax is
// refused.
func TestA2AE2EEKeyIDOnTheWire(t *testing.T) {
	store := newTestStore(t, "m1")
	m := newA2AE2EEState("txn", store.machine("m1"))
	var init []byte
	if err := m.ensureClientHandshake(context.Background(), nil, nil, func(p []byte) error { init = p; return errors.New("stop") }); err == nil {
		t.Fatal("want the stop")
	}
	if got := string(init[a2aE2EEPubLen+a2aE2EEPairingTagLen:]); got != "m1.1" {
		t.Fatalf("init key id = %q", got)
	}
	r := newA2AE2EEState("txn", store)
	if err := r.ensureClientHandshake(context.Background(), nil, nil, func(p []byte) error { init = p; return errors.New("stop") }); err == nil {
		t.Fatal("want the stop")
	}
	if len(init) != a2aE2EEPubLen+a2aE2EEPairingTagLen {
		t.Fatalf("root init is %d bytes, want %d (unchanged wire)", len(init), a2aE2EEPubLen+a2aE2EEPairingTagLen)
	}
	long := append(append([]byte(nil), init...), strings.Repeat("x", a2aE2EEKeyIDMax+1)...)
	if _, _, err := newServerA2AE2EEState("txn", long, store); err == nil || !errors.Is(err, errA2AE2EEPairing) {
		t.Fatalf("an over-long key id: %v", err)
	}
}
