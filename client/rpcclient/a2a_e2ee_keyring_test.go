// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// Per-machine keys (A2AE2EEKeyring): one test per invariant of nfltr's
// spec/a2akeys/MachineKeys.tla at this layer. PinNeverSilentlyReplaced is
// structural here: A2AE2EEKeyring has no method that writes.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
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

// For: an agent ref names its machine before its first "-" (TENANTSID's
// <machine id>-<service>); a ref of no machine in the store is a root
// holder's, under the root key.
func (s *testStore) For(ref string) (string, []byte, error) {
	name, _, _ := strings.Cut(ref, "-")
	s.mu.Lock()
	defer s.mu.Unlock()
	gen, ok := s.gen[name]
	if !ok {
		return "", s.root, nil
	}
	if s.rev[name] {
		return "", nil, fmt.Errorf("machine key %s.%d is revoked", name, gen)
	}
	return name + "." + strconv.Itoa(gen), testMachineKey(s.root, name, gen), nil
}

func (*testStore) Machine() bool { return false }

func (s *testStore) Valid(id string) bool {
	if id == "" {
		return true
	}
	name, g, _ := strings.Cut(id, ".")
	gen, _ := strconv.Atoi(g)
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.gen[name]
	return ok && cur == gen && !s.rev[name]
}

type testMachine struct {
	id  string
	key []byte
}

func (m testMachine) For(string) (string, []byte, error) { return m.id, m.key, nil }

func (m testMachine) Valid(id string) bool { return id == m.id }
func (testMachine) Machine() bool          { return true }

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

// A root holder and a machine talk both ways.
func TestA2AE2EEKeyringRootAndMachine(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m1, _, _ := echoPair(t, ctx, keyedAgent("m1-kr", store.machine("m1")), keyedAgent("hub-kr", store), &testRelay{})
	invokeOK(t, m1, "hub-kr")
	hub, _, _ := echoPair(t, ctx, keyedAgent("hub-kr2", store), keyedAgent("m1-node", store.machine("m1")), &testRelay{})
	invokeOK(t, hub, "m1-node")
}

// AcceptedIsSender: a machine cannot be accepted as another, by naming
// another machine's id (relay relabel, or a forged file) or calling another
// machine directly.
func TestA2AE2EEKeyringNoMachineSpeaksAsAnother(t *testing.T) {
	store := newTestStore(t, "m1", "m2")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The relay relabels m1's init: m2's key id, then m2's ref and key id.
	for _, fields := range [][2]string{{"m1-as", "m2.1"}, {"m2-as", "m2.1"}} {
		relabel := &testRelay{rewrite: func(fromA bool, f *pb.TunnelFrame) *pb.TunnelFrame {
			if fromA && f.GetMessageType() == a2aE2EEInitMessageType {
				f = cloneFrame(f)
				parts := bytes.SplitN(f.GetPayload(), []byte{0}, 4)
				f.Payload = append([]byte(fields[0]+"\x00"+string(parts[1])+"\x00"+fields[1]+"\x00"), parts[3]...)
			}
			return f
		}}
		caller, _, ran := echoPair(t, ctx, keyedAgent("m1-as", store.machine("m1")), keyedAgent("hub-as", store), relabel)
		invokeRefused(t, caller, "hub-as", ran)
	}
	m1 := store.machine("m1").(testMachine)
	forged, _, ran := echoPair(t, ctx, keyedAgent("m2-forged", testMachine{id: "m2.1", key: m1.key}), keyedAgent("hub-as2", store), &testRelay{})
	invokeRefused(t, forged, "hub-as2", ran)
	peer, _, ran := echoPair(t, ctx, keyedAgent("m1-b", m1), keyedAgent("m2-x", store.machine("m2")), &testRelay{})
	invokeRefused(t, peer, "m2-x", ran)
}

// NoMessageFromRevokedMachine and OtherMachinesUnaffected: after revoking
// m1 its handshakes are refused both ways while m2
// is served; rotating m1 refuses its old file and admits the new one.
func TestA2AE2EEKeyringRevokeRefusesOnlyThatMachine(t *testing.T) {
	store := newTestStore(t, "m1", "m2")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	oldM1 := store.machine("m1")
	m1, _, m1Ran := echoPair(t, ctx, keyedAgent("m1-rv", oldM1), keyedAgent("hub-rv1", store), &testRelay{})
	m2, _, _ := echoPair(t, ctx, keyedAgent("m2-rv", store.machine("m2")), keyedAgent("hub-rv2", store), &testRelay{})
	hub1, _, node1Ran := echoPair(t, ctx, keyedAgent("hub-rv3", store), keyedAgent("m1-node", oldM1), &testRelay{})
	hub2, _, _ := echoPair(t, ctx, keyedAgent("hub-rv4", store), keyedAgent("m2-node", store.machine("m2")), &testRelay{})
	invokeOK(t, m1, "hub-rv1")
	invokeOK(t, hub1, "m1-node")

	store.revoke("m1")
	m1Ran.Store(0)
	node1Ran.Store(0)
	invokeRefused(t, m1, "hub-rv1", m1Ran)
	invokeRefused(t, hub1, "m1-node", node1Ran)
	invokeOK(t, m2, "hub-rv2")
	invokeOK(t, hub2, "m2-node")

	store.rotate("m1")
	invokeRefused(t, m1, "hub-rv1", m1Ran)
	m1New, _, _ := echoPair(t, ctx, keyedAgent("m1-new", store.machine("m1")), keyedAgent("hub-rv5", store), &testRelay{})
	invokeOK(t, m1New, "hub-rv5")
	invokeOK(t, m2, "hub-rv2")
}

// NoMessageFromRevokedMachine for frames: a revoke ends calls in flight at
// their next frame, both directions (machine calling the root, root calling
// the machine), and a call of another machine goes on.
// keyedCall is an echo call between two keyed agents over a test relay.
type keyedCall struct {
	a, b    *Agent
	cs      ClientStream
	handled chan error // the handler's end
}

func openKeyedCall(ctx context.Context, t *testing.T, callerKR, targetKR A2AE2EEKeyring, callerID, targetID string) keyedCall {
	t.Helper()
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
	return keyedCall{a, b, cs, handled}
}

func (c keyedCall) roundTrip() error {
	if err := c.cs.Send([]byte("hi")); err != nil {
		return err
	}
	r, err := c.cs.Recv()
	if err == nil && string(r.Data) != "echo:hi" {
		err = fmt.Errorf("got %q", r.Data)
	}
	return err
}

func TestA2AE2EEKeyringRevokeEndsCallsInFlight(t *testing.T) {
	store := newTestStore(t, "m1", "m2")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	toRoot := openKeyedCall(ctx, t, store.machine("m1"), store, "m1-fl", "hub-fl")
	fromRoot := openKeyedCall(ctx, t, store, store.machine("m1"), "hub-fl2", "m1-node")
	other := openKeyedCall(ctx, t, store.machine("m2"), store, "m2-fl", "hub-fl3")
	for _, c := range []keyedCall{toRoot, fromRoot, other} {
		if err := c.roundTrip(); err != nil {
			t.Fatalf("before the revoke: %v", err)
		}
	}

	store.revoke("m1")
	// m1 calling the root: its next frame is refused at the root, whose
	// handler's Recv fails, and the call ends with that refusal.
	if err := toRoot.roundTrip(); err == nil || !strings.Contains(err.Error(), "revoked or rotated") {
		t.Fatalf("m1's frame after the revoke: err = %v, want the revoke", err)
	}
	if err := <-toRoot.handled; err == nil || !strings.Contains(err.Error(), "revoked or rotated") {
		t.Fatalf("root's handler after the revoke: %v", err)
	}
	// The root calling m1: the root seals nothing more under m1's key.
	if err := fromRoot.cs.Send([]byte("hi")); err == nil || !strings.Contains(err.Error(), "revoked or rotated") {
		t.Fatalf("root's frame to m1 after the revoke: err = %v", err)
	}
	if err := other.roundTrip(); err != nil {
		t.Fatalf("m2's call after m1's revoke: %v", err)
	}
}

// RecheckA2AE2EE ends calls idle mid-stream at once: after the revoke no
// frame is sent, and both ends of each of m1's calls end within a short
// bound; m2's call goes on.
func TestA2AE2EERecheckEndsIdleCallsAtOnce(t *testing.T) {
	store := newTestStore(t, "m1", "m2")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	toRoot := openKeyedCall(ctx, t, store.machine("m1"), store, "m1-fl", "hub-fl")
	fromRoot := openKeyedCall(ctx, t, store, store.machine("m1"), "hub-fl2", "m1-node")
	other := openKeyedCall(ctx, t, store.machine("m2"), store, "m2-fl", "hub-fl3")
	recvs := map[string]chan error{}
	for name, c := range map[string]keyedCall{"toRoot": toRoot, "fromRoot": fromRoot} {
		if err := c.roundTrip(); err != nil {
			t.Fatalf("%s before the revoke: %v", name, err)
		}
		ch := make(chan error, 1)
		go func() { _, err := c.cs.Recv(); ch <- err }() // idle: no frame comes
		recvs[name] = ch
	}
	if err := other.roundTrip(); err != nil {
		t.Fatalf("m2 before the revoke: %v", err)
	}

	store.revoke("m1")
	for _, c := range []keyedCall{toRoot, fromRoot, other} {
		c.a.RecheckA2AE2EE()
		c.b.RecheckA2AE2EE()
	}
	within := func(what string, ch chan error, want string) {
		t.Helper()
		select {
		case err := <-ch:
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s: err = %v, want %q", what, err, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not end after the recheck", what)
		}
	}
	// m1 calling the root: the root's handler ends with the revoke, m1's
	// Recv with the root's refusal (in the clear: the relay's word only).
	within("root's handler", toRoot.handled, "revoked or rotated")
	within("m1's Recv", recvs["toRoot"], "revoked or rotated")
	// The root calling m1: the root's Recv ends with the revoke, m1's
	// handler with the root's cancel.
	within("root's Recv", recvs["fromRoot"], "revoked or rotated")
	within("m1's handler", fromRoot.handled, "canceled")
	// The root's sessions under m1's key went with them.
	fromRoot.a.sessions.mu.Lock()
	toRoot.b.sessions.mu.Lock()
	out, in := len(fromRoot.a.sessions.out), len(toRoot.b.sessions.in)
	toRoot.b.sessions.mu.Unlock()
	fromRoot.a.sessions.mu.Unlock()
	if out != 0 || in != 0 {
		t.Fatalf("root's sessions under m1's key after the recheck: out %d in %d", out, in)
	}
	if err := other.roundTrip(); err != nil {
		t.Fatalf("m2's call after m1's revoke: %v", err)
	}
}

// The init is caller 0 callee 0 key id 0 message 1: a machine names its
// own key id, a root holder calling a root holder "" (message 1 of
// NNpsk0, 48 bytes), and an id longer than a2aE2EEKeyIDMax is refused.
func TestA2AE2EEKeyIDOnTheWire(t *testing.T) {
	store := newTestStore(t, "m1")
	initOf := func(caller, callee string, kr A2AE2EEKeyring) []byte {
		var init []byte
		s := newA2AE2EEState("txn", caller, callee, kr)
		if err := s.ensureClientHandshake(context.Background(), nil, nil, func(_ string, p []byte) error { init = p; return errors.New("stop") }); err == nil {
			t.Fatal("want the stop")
		}
		return init
	}
	if got, want := initOf("m1-a", "hub-a", store.machine("m1")), "m1-a\x00hub-a\x00m1.1\x00"; len(got) != len(want)+a2aE2EEKeyedMsg1Len || string(got[:len(want)]) != want {
		t.Fatalf("machine init = %q", got)
	}
	if got, want := initOf("hub-b", "m1-node", store), "hub-b\x00m1-node\x00m1.1\x00"; string(got[:len(want)]) != want {
		t.Fatalf("root to machine init = %q", got)
	}
	root := initOf("hub-b", "hub-c", store)
	if want := "hub-b\x00hub-c\x00\x00"; len(root) != len(want)+a2aE2EEKeyedMsg1Len || string(root[:len(want)]) != want {
		t.Fatalf("root to root init = %q", root)
	}
	parts := bytes.SplitN(root, []byte{0}, 4)
	long := append([]byte("hub-b\x00hub-c\x00"+strings.Repeat("x", a2aE2EEKeyIDMax+1)+"\x00"), parts[3]...)
	if _, _, err := newServerA2AE2EEState("txn", "hub-c", long, store, true, rand.Reader); err == nil || !errors.Is(err, errA2AE2EEPairing) {
		t.Fatalf("an over-long key id: %v", err)
	}
}

// testRootOf is a root holder that calls m's machine under m's key.
type testRootOf struct{ testMachine }

func (testRootOf) Machine() bool { return false }

// notifyingStore is a testStore that says when it changed
// (A2AE2EEKeyringChanges).
type notifyingStore struct {
	*testStore
	mu      sync.Mutex
	changed []func()
}

func (s *notifyingStore) OnChange(_ context.Context, f func()) {
	s.mu.Lock()
	s.changed = append(s.changed, f)
	s.mu.Unlock()
}

func (s *notifyingStore) revoke(name string) {
	s.testStore.revoke(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.changed {
		f()
	}
}

// A keyring that says when it changed ends an idle call on the revoke
// itself: the agent rechecks on the change, nobody calls RecheckA2AE2EE.
func TestA2AE2EEKeyringChangesEndIdleCalls(t *testing.T) {
	store := &notifyingStore{testStore: newTestStore(t, "m1")}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := openKeyedCall(ctx, t, store, store.machine("m1"), "hub-fl", "m1-node")
	if err := c.roundTrip(); err != nil {
		t.Fatal(err)
	}
	recv := make(chan error, 1)
	go func() { _, err := c.cs.Recv(); recv <- err }()
	store.revoke("m1")
	select {
	case err := <-recv:
		if err == nil || !strings.Contains(err.Error(), "revoked or rotated") {
			t.Fatalf("Recv after the revoke: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the call did not end on the change")
	}
	select {
	case err := <-c.handled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("m1's handler: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("m1's handler did not end")
	}
}
