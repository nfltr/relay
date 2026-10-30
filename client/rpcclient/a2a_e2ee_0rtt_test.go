// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// detRand is a deterministic byte stream (SHA-256 chained from a seed) for
// the key-schedule vectors.
type detRand struct {
	state [32]byte
	buf   []byte
}

func newDetRand(seed string) *detRand { return &detRand{state: sha256.Sum256([]byte(seed))} }

func (r *detRand) Read(p []byte) (int, error) {
	for i := range p {
		if len(r.buf) == 0 {
			r.state = sha256.Sum256(r.state[:])
			r.buf = r.state[:]
		}
		p[i], r.buf = r.buf[0], r.buf[1:]
	}
	return len(p), nil
}

var vectorTime = time.UnixMilli(1760000000000)

// flight is one first flight from a fresh initiator state to st.
func flight(t testing.TB, st *a2aE2EEStatic, pairing []byte, txnID string, data []byte, now time.Time, rng io.Reader) (*a2aE2EEState, []byte) {
	t.Helper()
	s := newA2AE2EEState(txnID, pairing)
	s.peerStatic, s.peerName = st.key.Public, "node-1"
	payload, ok, err := s.firstFlight(data, now, rng)
	if !ok || err != nil {
		t.Fatalf("firstFlight: ok=%v err=%v", ok, err)
	}
	return s, payload
}

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:8]) }

// The key schedule for fixed keys, timestamp, txn id and randomness, both
// modes: the first flight, message 2 and each direction's key. The Noise
// part is github.com/flynn/noise (checked against the cacophony vectors
// there); these pin what this package feeds it and takes from it.
func TestA2AE2EE0RTTKeyScheduleVectors(t *testing.T) {
	key := testPairingKey(t, secretA)
	for _, tc := range []struct {
		name                       string
		pairing                    []byte
		label, flight, ack, i2r, r2i string
	}{
		{"unkeyed", nil, "k8V-LhDYv9TJL9GV5EXXglIdVcl1652QU6lrcS6qs0o",
			"1b1e5d1a90e82dff", "f5726075d0709d7a", "5e80c25ddadb9e46", "90a50efcaac91f69"},
		{"pairing key", key, "k8V-LhDYv9TJL9GV5EXXglIdVcl1652QU6lrcS6qs0o.QH8iKcU6EuHkB8AlqD6X1_ksdEmFDysoG1qvTCsfVzM.node-1",
			"d492fe742462ac62", "2fedc9f5c4e14805", "0916cadbe19c543a", "75ffa32300ed5afd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := newA2AE2EEStatic(newDetRand("responder static"))
			if err != nil {
				t.Fatal(err)
			}
			s, payload := flight(t, st, tc.pairing, "txn-vector", []byte("launch an agent"), vectorTime, newDetRand("initiator"))
			acc, _, refusal := st.accept(tc.pairing, "txn-vector", payload, vectorTime.Add(time.Second), newDetRand("responder"))
			if refusal != 0 || string(acc.request) != "launch an agent" {
				t.Fatalf("accept: refusal %d, request %q", refusal, acc.request)
			}
			if err := s.complete(acc.ack); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(s.key, acc.state.recvKey) || !bytes.Equal(s.recvKey, acc.state.key) || bytes.Equal(s.key, s.recvKey) {
				t.Fatal("the two ends' directional keys differ, or both directions share one")
			}
			got := map[string]string{
				"label":  st.label("node-1", tc.pairing),
				"flight": hexSum(payload), "ack": hexSum(acc.ack),
				"i2r": hex.EncodeToString(s.key[:8]), "r2i": hex.EncodeToString(s.recvKey[:8]),
			}
			want := map[string]string{"label": tc.label, "flight": tc.flight, "ack": tc.ack, "i2r": tc.i2r, "r2i": tc.r2i}
			for k := range want {
				if got[k] != want[k] {
					t.Errorf("%s = %q, want %q", k, got[k], want[k])
				}
			}
		})
	}
}

// learn puts target's advertised label in the book for the test.
func learn(t *testing.T, target *Agent, pairing []byte) string {
	t.Helper()
	v := target.e2eeStatic().label(target.agentID, pairing)
	LearnA2AE2EEPeer(target.agentID, map[string]string{A2AE2EEStaticLabel: v})
	t.Cleanup(func() { LearnA2AE2EEPeer(target.agentID, nil) })
	return v
}

func frameTypes(fs []*pb.TunnelFrame) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.GetMessageType()
	}
	return out
}

func noPlaintext(t *testing.T, r *testRelay, secret string) {
	t.Helper()
	for _, f := range r.sentByA() {
		if bytes.Contains(f.GetPayload(), []byte(secret)) {
			t.Fatalf("the caller sent %q in the clear: %v", secret, f)
		}
	}
}

func TestA2AE2EE0RTTRoundTrip(t *testing.T) {
	key := testPairingKey(t, secretA)
	for _, tc := range []struct {
		name string
		key  []byte
	}{{"unkeyed", nil}, {"pairing key", key}} {
		t.Run(tc.name, func(t *testing.T) {
			const latency = 100 * time.Millisecond // one way: a round trip is 200 ms
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// While hold is set, the relay passes on nothing of the caller's
			// after the first flight until the call has its reply: a call
			// that needs a second flight to the peer never completes.
			var hold atomic.Pointer[chan struct{}]
			relay := &testRelay{latency: latency}
			relay.rewrite = func(fromA bool, f *pb.TunnelFrame) *pb.TunnelFrame {
				if replied := hold.Load(); fromA && replied != nil && f.GetMessageType() != a2aE2EEInit0RTTMessageType {
					select {
					case <-*replied:
					case <-ctx.Done():
					}
				}
				return f
			}
			caller, target, ran := echoPair(t, ctx, pairedAgent("zr-hub", tc.key), pairedAgent("zr-node", tc.key), relay)

			t0 := time.Now()
			got, err := caller.Invoke(ctx, "zr-node", []byte("SECRET-BRIEF"))
			interactive := time.Since(t0)
			if err != nil || string(got) != "echo:SECRET-BRIEF" {
				t.Fatalf("interactive Invoke = %q, %v", got, err)
			}
			// The handshake first, then the request and its end.
			const interactiveFrames = 3
			if types := frameTypes(relay.awaitSentByA(ctx, t, interactiveFrames)); strings.Join(types, ",") != a2aE2EEInitMessageType+",a2a-request,a2a-request" {
				t.Fatalf("interactive call sent %v", types)
			}

			learn(t, target, tc.key)
			replied := make(chan struct{})
			hold.Store(&replied)
			t0 = time.Now()
			got, err = caller.Invoke(ctx, "zr-node", []byte("SECRET-BRIEF"))
			zeroRTT := time.Since(t0)
			close(replied)
			if err != nil || string(got) != "echo:SECRET-BRIEF" {
				t.Fatalf("0-RTT Invoke = %q, %v (a call that needs more than its first flight never gets the reply)", got, err)
			}
			// The end of the request reaches the relay after the reply.
			if types := frameTypes(relay.awaitSentByA(ctx, t, interactiveFrames+2)[interactiveFrames:]); strings.Join(types, ",") != a2aE2EEInit0RTTMessageType+",a2a-request" {
				t.Fatalf("0-RTT call sent %v, want the first flight then the end of the request", types)
			}
			noPlaintext(t, relay, "SECRET-BRIEF")
			if ran.Load() != 2 {
				t.Fatalf("handler ran %d times, want 2", ran.Load())
			}
			// One flight to the peer and its reply, against two round trips
			// for the handshake first.
			t.Logf("interactive %s, 0-RTT %s", interactive.Round(time.Millisecond), zeroRTT.Round(time.Millisecond))
			if interactive < 4*latency {
				t.Fatalf("interactive %s, want >= 2 round trips", interactive)
			}
		})
	}
}

// A stream's later frames wait for the ack, then use the call's keys.
func TestA2AE2EE0RTTStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msA, msB := newMockStream(ctx), newMockStream(ctx)
	caller, target := pairedAgent("zr-hub", nil)(msA), pairedAgent("zr-node", nil)(msB)
	defer caller.Close() //nolint:errcheck
	defer target.Close() //nolint:errcheck
	target.Handle(func(s ServerStream) error {
		for {
			data, err := s.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if err := s.Send(append([]byte("echo:"), data...)); err != nil {
				return err
			}
		}
	})
	(&testRelay{}).run(ctx, msA, msB)
	learn(t, target, nil)
	cs, err := caller.NewStream(ctx, "zr-node")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"one", "two", "three"} {
		if err := cs.Send([]byte(m)); err != nil {
			t.Fatal(err)
		}
		resp, err := cs.Recv()
		if err != nil || string(resp.Data) != "echo:"+m {
			t.Fatalf("Recv = %v, %v", resp, err)
		}
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Recv(); err != io.EOF {
		t.Fatalf("after CloseSend: %v", err)
	}
}

func TestA2AE2EE0RTTWindow(t *testing.T) {
	st, _ := newA2AE2EEStatic(newDetRand("window"))
	for _, tc := range []struct {
		skew time.Duration
		want a2aE2EERefusal
	}{
		{59 * time.Second, 0},
		{-59 * time.Second, 0},
		{61 * time.Second, refuseClock},
		{-61 * time.Second, refuseClock},
	} {
		_, payload := flight(t, st, nil, "txn", []byte("x"), vectorTime, newDetRand(tc.skew.String()))
		if _, _, r := st.accept(nil, "txn", payload, vectorTime.Add(tc.skew), newDetRand("r")); r != tc.want {
			t.Errorf("responder clock %s from the flight's: refusal %d, want %d", tc.skew, r, tc.want)
		}
	}
}

// A flight is taken once: a copy reads replay, before or after it was
// taken, and so does the original after a tampered copy was refused (every
// ephemeral key is burned first).
func TestA2AE2EE0RTTReplayAndTamperRefused(t *testing.T) {
	key := testPairingKey(t, secretA)
	st, _ := newA2AE2EEStatic(newDetRand("replay"))
	now := vectorTime
	_, payload := flight(t, st, key, "txn", []byte("x"), now, newDetRand("a"))
	if _, _, r := st.accept(key, "txn", payload, now, newDetRand("r")); r != 0 {
		t.Fatalf("first: %d", r)
	}
	if _, _, r := st.accept(key, "txn", payload, now.Add(119*time.Second), newDetRand("r")); r != refuseReplay {
		t.Fatalf("replay within two windows: %d", r)
	}
	if _, _, r := st.accept(key, "txn", payload, now.Add(121*time.Second), newDetRand("r")); r != refuseClock {
		t.Fatalf("replay after two windows: %d, want clock", r)
	}

	regions := map[string]int{"version": 0, "timestamp": 5, "static": 20, "ephemeral": 50, "early key": 90, "request": len(payload) - 1}
	for name, i := range regions {
		_, payload := flight(t, st, key, "txn-"+name, []byte("x"), now, newDetRand(name))
		tampered := append([]byte(nil), payload...)
		tampered[i] ^= 1
		if _, _, r := st.accept(key, "txn-"+name, tampered, now, newDetRand("r")); r == 0 {
			t.Errorf("tampered %s accepted", name)
		}
		_, _, r := st.accept(key, "txn-"+name, payload, now, newDetRand("r"))
		want := refuseReplay // its ephemeral key was burned by the tampered copy
		if name == "ephemeral" {
			want = 0 // the copy burned another key
		}
		if r != want {
			t.Errorf("original after a tampered %s copy: refusal %d, want %d", name, r, want)
		}
	}
	// Another txn id, the same flight: the prologue binds it.
	_, payload = flight(t, st, key, "txn-a", []byte("x"), now, newDetRand("txn"))
	if _, _, r := st.accept(key, "txn-b", payload, now, newDetRand("r")); r != refuseBad {
		t.Fatalf("flight under another txn id: %d", r)
	}
}

func TestA2AE2EE0RTTRegisterBounded(t *testing.T) {
	st, _ := newA2AE2EEStatic(newDetRand("bounded"))
	now := vectorTime
	for i := range a2aE2EE0RTTSeenMax {
		var k [a2aE2EEPubLen]byte
		k[0], k[1], k[2] = byte(i), byte(i>>8), 0xff
		st.seen[k] = now.Add(time.Minute)
	}
	_, payload := flight(t, st, nil, "txn", []byte("x"), now, newDetRand("a"))
	if _, _, r := st.accept(nil, "txn", payload, now, newDetRand("r")); r != refuseBusy {
		t.Fatalf("full register: %d", r)
	}
	// The entries expire, but a flight refused busy must never be taken.
	_, payload = flight(t, st, nil, "txn", []byte("x"), now.Add(119*time.Second), newDetRand("b"))
	if _, _, r := st.accept(nil, "txn", payload, now.Add(119*time.Second), newDetRand("r")); r != refuseBusy {
		t.Fatalf("within two windows of filling: %d", r)
	}
	_, payload = flight(t, st, nil, "txn", []byte("x"), now.Add(121*time.Second), newDetRand("c"))
	if _, _, r := st.accept(nil, "txn", payload, now.Add(121*time.Second), newDetRand("r")); r != 0 {
		t.Fatalf("after: %d", r)
	}
	if len(st.seen) != 1 {
		t.Fatalf("register kept %d expired entries", len(st.seen)-1)
	}
}

// A responder that restarted (another static key) refuses the flight, and
// the call takes the interactive handshake: it succeeds, the request runs
// once, and the stale key leaves the book.
func TestA2AE2EE0RTTStaleKeyTakesHandshake(t *testing.T) {
	key := testPairingKey(t, secretA)
	for _, tc := range []struct {
		name string
		key  []byte
	}{{"unkeyed", nil}, {"pairing key", key}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			relay := &testRelay{}
			caller, target, ran := echoPair(t, ctx, pairedAgent("zr-hub", tc.key), pairedAgent("zr-node", tc.key), relay)
			stale := learn(t, target, tc.key)
			restarted, _ := newA2AE2EEStatic(newDetRand("restarted " + tc.name))
			target.a2aStatic.Store(restarted)
			got, err := caller.Invoke(ctx, "zr-node", []byte("SECRET-BRIEF"))
			if err != nil || string(got) != "echo:SECRET-BRIEF" || ran.Load() != 1 {
				t.Fatalf("Invoke to a restarted responder = %q, %v, ran %d", got, err, ran.Load())
			}
			want := strings.Join([]string{a2aE2EEInit0RTTMessageType, a2aE2EEInitMessageType, "a2a-request", "a2a-request"}, ",")
			if types := strings.Join(frameTypes(relay.awaitSentByA(ctx, t, 4)), ","); types != want {
				t.Fatalf("caller sent %s, want %s", types, want)
			}
			noPlaintext(t, relay, "SECRET-BRIEF")
			if v := a2aE2EEPeer("zr-node"); v == stale {
				t.Fatal("the stale key stayed in the book")
			}
		})
	}
}

// With a pairing key the relay can neither forge a refusal (to have a taken
// request sent again) nor pass another agent's refusal off as the target's.
func TestA2AE2EE0RTTForgedRetryRejected(t *testing.T) {
	key := testPairingKey(t, secretA)
	for _, tc := range []struct {
		name  string
		forge func(f *pb.TunnelFrame, e []byte) []byte
	}{
		{"no tag", func(*pb.TunnelFrame, []byte) []byte { return []byte{byte(refuseStale)} }},
		{"another agent's refusal", func(f *pb.TunnelFrame, e []byte) []byte {
			return retryPayload(key, "zr-other", f.GetTransactionId(), e, refuseStale)
		}},
		{"a replay refusal", func(f *pb.TunnelFrame, e []byte) []byte {
			return retryPayload(key, "zr-node", f.GetTransactionId(), e, refuseReplay)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var e atomic.Value
			relay := &testRelay{}
			relay.rewrite = func(fromA bool, f *pb.TunnelFrame) *pb.TunnelFrame {
				if fromA && f.GetMessageType() == a2aE2EEInit0RTTMessageType {
					e.Store(append([]byte(nil), f.GetPayload()[41:73]...))
				}
				if !fromA && f.GetMessageType() == a2aE2EEAckMessageType {
					// The request was taken; the relay withholds the ack.
					return &pb.TunnelFrame{MessageType: a2aE2EERetryMessageType, TransactionId: f.GetTransactionId(), Payload: tc.forge(f, e.Load().([]byte))}
				}
				return f
			}
			caller, target, ran := echoPair(t, ctx, pairedAgent("zr-hub", key), pairedAgent("zr-node", key), relay)
			learn(t, target, key)
			_, err := caller.Invoke(ctx, "zr-node", []byte("SECRET-BRIEF"))
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("Invoke with a forged refusal: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			if ran.Load() != 1 {
				t.Fatalf("the request ran %d times", ran.Load())
			}
			for _, f := range relay.sentByA() {
				if f.GetMessageType() == a2aE2EEInitMessageType {
					t.Fatal("the caller retried on a refusal it must not trust")
				}
			}
		})
	}
}

// A label is used only when it proves the caller's pairing key: a relay
// that swaps the advertised key (or a responder with another key) gets the
// interactive handshake, which refuses or succeeds as without 0-RTT.
func TestA2AE2EE0RTTLabelMustProvePairingKey(t *testing.T) {
	key, other := testPairingKey(t, secretA), testPairingKey(t, strings.Repeat("z", 40))
	relayStatic, _ := newA2AE2EEStatic(newDetRand("relay"))
	for _, tc := range []struct {
		name      string
		label     func(target *Agent) string
		responder []byte
		wantErr   string
	}{
		{"relay swapped the key", func(target *Agent) string {
			genuine := target.e2eeStatic().label("zr-node", key)
			return a2aE2EEB64.EncodeToString(relayStatic.key.Public) + genuine[strings.Index(genuine, "."):]
		}, key, ""},
		{"relay's own unkeyed label", func(*Agent) string { return relayStatic.label("zr-node", nil) }, key, ""},
		{"responder's other pairing key", func(target *Agent) string { return target.e2eeStatic().label("zr-node", other) }, other, "failed pairing-key verification"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			relay := &testRelay{}
			caller, target, ran := echoPair(t, ctx, pairedAgent("zr-hub", key), pairedAgent("zr-node", tc.responder), relay)
			LearnA2AE2EEPeer("zr-node", map[string]string{A2AE2EEStaticLabel: tc.label(target)})
			t.Cleanup(func() { LearnA2AE2EEPeer("zr-node", nil) })
			got, err := caller.Invoke(ctx, "zr-node", []byte("SECRET-BRIEF"))
			if first := relay.sentByA()[0].GetMessageType(); first != a2aE2EEInitMessageType {
				t.Fatalf("first frame %s: the caller trusted an unproven label", first)
			}
			if tc.wantErr == "" && (err != nil || string(got) != "echo:SECRET-BRIEF") {
				t.Fatalf("Invoke = %q, %v", got, err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr) || ran.Load() != 0) {
				t.Fatalf("Invoke = %v, ran %d; want %q", err, ran.Load(), tc.wantErr)
			}
		})
	}
	// The responder side: a flight under another pairing key is refused.
	st, _ := newA2AE2EEStatic(newDetRand("pk"))
	_, payload := flight(t, st, key, "txn", []byte("x"), vectorTime, newDetRand("a"))
	if _, _, r := st.accept(other, "txn", payload, vectorTime, newDetRand("r")); r != refuseBad {
		t.Fatalf("flight under another pairing key: %d", r)
	}
	_, payload = flight(t, st, key, "txn", []byte("x"), vectorTime, newDetRand("b"))
	if _, _, r := st.accept(nil, "txn", payload, vectorTime, newDetRand("r")); r != refuseBad {
		t.Fatalf("keyed flight to an unkeyed responder: %d", r)
	}
}

// Without a pairing key nothing is authenticated, as in the interactive
// handshake: a relay that swaps the label reads the first flight. Pinned so
// the claim stays honest; the pairing key closes it (above).
func TestA2AE2EE0RTTWithoutPairingKeyIsOpenToAnActiveRelay(t *testing.T) {
	relayStatic, _ := newA2AE2EEStatic(newDetRand("relay"))
	s := newA2AE2EEState("txn", nil)
	s.peerStatic, _, _ = parseA2AE2EEStaticLabel(relayStatic.label("zr-node", nil), nil)
	payload, _, _ := s.firstFlight([]byte("SECRET-BRIEF"), vectorTime, newDetRand("a"))
	acc, _, r := relayStatic.accept(nil, "txn", payload, vectorTime, newDetRand("r"))
	if r != 0 || string(acc.request) != "SECRET-BRIEF" {
		t.Fatal("expected an unkeyed first flight to be readable by the holder of the swapped key")
	}
}

func FuzzA2AE2EE0RTTAccept(f *testing.F) {
	sum := sha256.Sum256([]byte(a2aE2EEPairingKeyContext + secretA))
	key := sum[:]
	st, _ := newA2AE2EEStatic(newDetRand("fuzz"))
	for _, k := range [][]byte{nil, key} {
		_, payload := flight(f, st, k, "txn", []byte("request"), vectorTime, newDetRand("seed"))
		f.Add(payload, k != nil)
	}
	f.Add([]byte{}, false)
	f.Add(make([]byte, a2aE2EE0RTTMinLen), true)
	f.Fuzz(func(t *testing.T, payload []byte, keyed bool) {
		st := &a2aE2EEStatic{key: st.key, seen: map[[a2aE2EEPubLen]byte]time.Time{}}
		pairing := []byte(nil)
		if keyed {
			pairing = key
		}
		acc, e, r := st.accept(pairing, "txn", payload, vectorTime, newDetRand("r"))
		if r == 0 && (acc.state == nil || len(acc.ack) == 0 || len(e) != a2aE2EEPubLen) {
			t.Fatalf("accepted without a state, ack or ephemeral key")
		}
		_ = retryPayload(pairing, "n", "txn", e, r)
	})
}
