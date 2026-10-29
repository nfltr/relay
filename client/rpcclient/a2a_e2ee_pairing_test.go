// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func pairingKeyFile(t *testing.T, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "e2ee.key")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testPairingKey(t *testing.T, secret string) []byte {
	t.Helper()
	key, err := LoadA2AE2EEPairingKey(pairingKeyFile(t, secret))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pairedAgent(id string, key []byte) func(AgentTunnel) *Agent {
	return func(s AgentTunnel) *Agent {
		a := e2eeAgent(id, false)(s)
		if key != nil {
			a.a2aPairingKey.Store(&key)
		}
		return a
	}
}

const secretA = "0123456789abcdef0123456789abcdef-machines-of-user-a"

// mitmRelay is an active relay: it answers each end's handshake with its own
// X25519 key and tries to read the request the caller then encrypts.
type mitmRelay struct {
	testRelay
	priv              *ecdh.PrivateKey
	swapInit, swapAck bool

	mu         sync.Mutex
	callerPub  []byte
	stolenText [][]byte
}

func newMITMRelay(t *testing.T, swapInit, swapAck bool) *mitmRelay {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &mitmRelay{priv: priv, swapInit: swapInit, swapAck: swapAck}
	m.rewrite = m.intercept
	return m
}

// swapPub replaces the leading public key and keeps whatever tag followed:
// the relay does not hold the pairing key, so it cannot compute a new one.
// allow:wrapper — names the attack step both swap directions use.
func (m *mitmRelay) swapPub(payload []byte) []byte {
	return append(append([]byte(nil), m.priv.PublicKey().Bytes()...), payload[a2aE2EEPubLen:]...)
}

func (m *mitmRelay) intercept(fromCaller bool, f *pb.TunnelFrame) *pb.TunnelFrame {
	f = cloneFrame(f)
	switch {
	case fromCaller && f.GetMessageType() == a2aE2EEInitMessageType:
		m.mu.Lock()
		m.callerPub = append([]byte(nil), f.GetPayload()[:a2aE2EEPubLen]...)
		m.mu.Unlock()
		if m.swapInit {
			f.Payload = m.swapPub(f.GetPayload())
		}
	case !fromCaller && f.GetMessageType() == a2aE2EEAckMessageType && m.swapAck:
		f.Payload = m.swapPub(f.GetPayload())
	case fromCaller && len(f.GetPayload()) > 0:
		m.tryRead(f)
	}
	return f
}

// tryRead decrypts a caller frame with the key the caller would share with
// the relay if it had accepted the relay's key (unkeyed v1 KDF).
func (m *mitmRelay) tryRead(f *pb.TunnelFrame) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.callerPub == nil {
		return
	}
	pub, err := ecdh.X25519().NewPublicKey(m.callerPub)
	if err != nil {
		return
	}
	shared, err := m.priv.ECDH(pub)
	if err != nil {
		return
	}
	if plain, err := newEstablishedA2AE2EEState(deriveA2AE2EEKey(shared)).decrypt(f.GetTransactionId(), f.GetPayload()); err == nil {
		m.stolenText = append(m.stolenText, plain)
	}
}

func (m *mitmRelay) stole(secret string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.stolenText {
		if bytes.Contains(p, []byte(secret)) {
			return true
		}
	}
	return false
}

func cloneFrame(f *pb.TunnelFrame) *pb.TunnelFrame {
	c := &pb.TunnelFrame{
		Payload: append([]byte(nil), f.GetPayload()...), MessageType: f.GetMessageType(), TransactionId: f.GetTransactionId(),
		Routing: f.GetRouting(), Eom: f.GetEom(), StatusCode: f.GetStatusCode(), StatusDetail: f.GetStatusDetail(), Timestamps: f.GetTimestamps(),
	}
	return c
}

// Without a pairing key the ephemeral keys are unauthenticated: an active
// relay that swaps them reads the caller's request. This is the gap the
// pairing key closes; the test pins it so the claim stays honest.
func TestA2AE2EEWithoutPairingKeyIsOpenToAnActiveRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	relay := newMITMRelay(t, true, true)
	caller, _, _ := echoPair(t, ctx, pairedAgent("hub", nil), pairedAgent("node-1", nil), &relay.testRelay)
	_, _ = caller.Invoke(ctx, "node-1", []byte("SECRET-BRIEF"))
	if !relay.stole("SECRET-BRIEF") {
		t.Fatal("expected the unauthenticated handshake to be readable by a key-swapping relay")
	}
}

func TestA2AE2EEPairingKeyRefusesRelayKeySwap(t *testing.T) {
	key := testPairingKey(t, secretA)
	for _, tc := range []struct {
		name              string
		swapInit, swapAck bool
		want              string
	}{
		// The responder refuses a swapped init; the caller sees its error.
		{"swap both keys", true, true, "failed pairing-key verification"},
		{"swap the caller's key", true, false, "failed pairing-key verification"},
		// The caller refuses a swapped ack itself.
		{"swap the responder's key", false, true, "failed pairing-key verification"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			relay := newMITMRelay(t, tc.swapInit, tc.swapAck)
			caller, _, ran := echoPair(t, ctx, pairedAgent("hub", key), pairedAgent("node-1", key), &relay.testRelay)
			_, err := caller.Invoke(ctx, "node-1", []byte("SECRET-BRIEF"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Invoke through a key-swapping relay: err = %v, want %q", err, tc.want)
			}
			if ran.Load() != 0 {
				t.Fatal("the responder ran a request over a swapped handshake")
			}
			if relay.stole("SECRET-BRIEF") {
				t.Fatal("the relay read the brief")
			}
			for _, f := range relay.sentByA() {
				if bytes.Contains(f.GetPayload(), []byte("SECRET-BRIEF")) {
					t.Fatal("the caller sent the brief in plaintext")
				}
			}
		})
	}
}

func TestA2AE2EEPairingKeyBothEnds(t *testing.T) {
	key := testPairingKey(t, secretA)
	other := testPairingKey(t, strings.Repeat("z", 40))
	for _, tc := range []struct {
		name          string
		callerKey     []byte
		responderKey  []byte
		wantErrSubstr string
	}{
		{"same key", key, key, ""},
		{"different keys", key, other, "failed pairing-key verification"},
		{"responder has none", key, nil, "pairing key this end does not have"},
		{"caller has none", nil, key, "did not authenticate its A2A E2EE key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			caller, _, ran := echoPair(t, ctx, pairedAgent("hub", tc.callerKey), pairedAgent("node-1", tc.responderKey), &testRelay{})
			got, err := caller.Invoke(ctx, "node-1", []byte("hi"))
			if tc.wantErrSubstr == "" {
				if err != nil || string(got) != "echo:hi" {
					t.Fatalf("paired call = %q, %v", got, err)
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), tc.wantErrSubstr) || !strings.Contains(err.Error(), "--e2ee-key-file") {
				t.Fatalf("err = %v, want FailedPrecondition with %q and the flag", err, tc.wantErrSubstr)
			}
			if ran.Load() != 0 {
				t.Fatal("request ran without a proven pairing key")
			}
		})
	}
}

// A pairing key declares the relay hostile: a keyed worker refuses
// relay-authored work (relay-owned dispatch, fleet-invoke) even though it
// opted in to serve it, since the relay could inject any task.assign.
func TestPairedAgentRefusesRelayAuthoredRequests(t *testing.T) {
	key := testPairingKey(t, secretA)
	for _, tc := range []struct{ source, mtype string }{
		{RelayAgentID, "a2a-request"},
		{"worker-1", fleetInvokeMessageType},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ms := newMockStream(ctx)
		worker := e2eeAgent("worker-1", true)(ms)
		worker.a2aPairingKey.Store(&key)
		var ran bool
		worker.Handle(func(s ServerStream) error { ran = true; return nil })
		ms.recvCh <- &pb.TunnelFrame{TransactionId: "txn-" + tc.mtype, MessageType: tc.mtype, Payload: []byte("task.assign"), Eom: true,
			Routing: &pb.RoutingInfo{AgentId: tc.source, TargetAgentId: "worker-1"}}
		reply := <-ms.sendCh
		if ran || reply.GetMessageType() != "error" || codes.Code(reply.GetStatusCode()) != codes.FailedPrecondition {
			t.Fatalf("keyed worker and relay-authored %s from %s: ran=%v reply=%v", tc.mtype, tc.source, ran, reply)
		}
		_ = worker.Close()
		cancel()
	}
}

func TestLoadA2AE2EEPairingKey(t *testing.T) {
	if _, err := LoadA2AE2EEPairingKey(pairingKeyFile(t, "short passphrase")); err == nil || !strings.Contains(err.Error(), "openssl rand -hex 32") {
		t.Fatalf("short secret: err = %v", err)
	}
	if _, err := LoadA2AE2EEPairingKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	a, b := testPairingKey(t, secretA), testPairingKey(t, "  "+secretA+"  ")
	if !bytes.Equal(a, b) || len(a) != 32 {
		t.Fatal("pairing key must ignore surrounding whitespace and be 32 bytes")
	}
}

func TestDialRejectsPairingKeyWithoutE2EE(t *testing.T) {
	_, err := Dial(context.Background(), "127.0.0.1:1", WithAgentID("a"), WithA2AE2EEPairingKeyFile(pairingKeyFile(t, secretA)))
	if err == nil || !strings.Contains(err.Error(), "needs E2EE on") {
		t.Fatalf("err = %v", err)
	}
	_, err = Dial(context.Background(), "127.0.0.1:1", WithAgentID("a"), WithA2AE2EE(), WithA2AE2EEPairingKeyFile(pairingKeyFile(t, "short")))
	if err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("err = %v", err)
	}
}
