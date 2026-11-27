// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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

// keyringOf is the keyring of a root pairing key.
func keyringOf(key []byte) A2AE2EEKeyring { return a2aE2EEPairingKey(key) }

func pairedAgent(id string, key []byte) func(AgentTunnel) *Agent {
	return keyedAgent(id, keyringOf(key))
}

func keyedAgent(id string, kr A2AE2EEKeyring) func(AgentTunnel) *Agent {
	return func(s AgentTunnel) *Agent {
		a := NewAgent(id, s)
		dir, err := os.MkdirTemp(replayBase, id+"-")
		if err != nil {
			panic(err)
		}
		if err := a.EnableA2AE2EEReplayRecord(dir); err != nil {
			panic(err)
		}
		if err := a.EnableA2AE2EE(kr); err != nil {
			panic(err)
		}
		return a
	}
}

const secretA = "0123456789abcdef0123456789abcdef-machines-of-user-a"

// mitmRelay is an active relay: it puts its own X25519 key in place of
// the caller's (init) or the responder's (ack) and keeps the rest; it does
// not hold the pairing key, so it cannot compute a new handshake.
type mitmRelay struct {
	testRelay
	priv              *ecdh.PrivateKey
	swapInit, swapAck bool
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

// swapPub replaces the X25519 key at off in payload.
func (m *mitmRelay) swapPub(payload []byte, off int) []byte {
	out := append([]byte(nil), payload...)
	copy(out[off:], m.priv.PublicKey().Bytes())
	return out
}

// initMsg1 is where message 1 starts in an init: after caller, callee and
// key id.
func initMsg1(payload []byte) int {
	off := 0
	for range 3 {
		off += bytes.IndexByte(payload[off:], 0) + 1
	}
	return off
}

func (m *mitmRelay) intercept(fromCaller bool, f *pb.TunnelFrame) *pb.TunnelFrame {
	f = cloneFrame(f)
	switch {
	case fromCaller && f.GetMessageType() == a2aE2EEInitMessageType && m.swapInit:
		f.Payload = m.swapPub(f.GetPayload(), initMsg1(f.GetPayload()))
	case !fromCaller && f.GetMessageType() == a2aE2EEAckMessageType && m.swapAck:
		f.Payload = m.swapPub(f.GetPayload(), 0)
	}
	return f
}

func cloneFrame(f *pb.TunnelFrame) *pb.TunnelFrame {
	return proto.Clone(f).(*pb.TunnelFrame) // every field, as a relay forwards it
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

// Keys declare the relay hostile: a keyed worker refuses relay-authored
// work (relay-owned dispatch, fleet-invoke), since the relay could inject
// any task.assign. There is no opt-in (keyed only).
func TestPairedAgentRefusesRelayAuthoredRequests(t *testing.T) {
	key := testPairingKey(t, secretA)
	for _, tc := range []struct{ source, mtype string }{
		{RelayAgentID, "a2a-request"},
		{"worker-1", "fleet-invoke"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ms := newMockStream(ctx)
		worker := pairedAgent("worker-1", key)(ms)
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

// Keyed only: E2EE without a key is refused before any dial.
func TestDialRejectsPairingKeyWithoutE2EE(t *testing.T) {
	_, err := Dial(context.Background(), "127.0.0.1:1", WithAgentID("a"), WithA2AE2EEPairingKeyFile(pairingKeyFile(t, secretA)))
	if err == nil || !strings.Contains(err.Error(), "needs E2EE on") {
		t.Fatalf("err = %v", err)
	}
	_, err = Dial(context.Background(), "127.0.0.1:1", WithAgentID("a"), WithA2AE2EE())
	if !errors.Is(err, ErrA2AE2EENoKey) {
		t.Fatalf("E2EE without a key: err = %v, want ErrA2AE2EENoKey", err)
	}
	if err := NewAgent("a", newMockStream(t.Context())).EnableA2AE2EE(nil); !errors.Is(err, ErrA2AE2EENoKey) {
		t.Fatalf("EnableA2AE2EE(nil): err = %v, want ErrA2AE2EENoKey", err)
	}
	_, err = Dial(context.Background(), "127.0.0.1:1", WithAgentID("a"), WithA2AE2EE(), WithA2AE2EEPairingKeyFile(pairingKeyFile(t, "short")))
	if err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("err = %v", err)
	}
}
