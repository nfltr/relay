// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// A2A E2EE wire v2 against a hostile relay: one test per finding of
// spec/proverif/README.md "Findings" (F1 reflection, F2 replay, drop,
// truncation and cleartext end and error frames, F3 reroute), each failing
// on v1.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// hostileRelay forwards frames between two mock streams; act returns, for
// each frame, the frames it sends back to the sender's side and on to the
// other side (nil act: forward as is).
type hostileRelay func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame)

func (act hostileRelay) run(ctx context.Context, a, b *mockStream) {
	pump := func(from, to *mockStream, fromA bool) {
		for {
			select {
			case f := <-from.sendCh:
				back, on := []*pb.TunnelFrame(nil), []*pb.TunnelFrame{f}
				if act != nil {
					back, on = act(fromA, f)
				}
				for _, g := range on {
					select {
					case to.recvCh <- g:
					case <-ctx.Done():
						return
					}
				}
				for _, g := range back {
					select {
					case from.recvCh <- g:
					case <-ctx.Done():
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}
	go pump(a, b, true)
	go pump(b, a, false)
}

// served records what a target's handler received.
type served struct {
	mu   sync.Mutex
	got  []string
	errs []error
}

func (s *served) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.got...)
}

// hostilePair connects caller and target through act; the target echoes
// every request until the caller's end of stream.
func hostilePair(t *testing.T, ctx context.Context, caller, target func(AgentTunnel) *Agent, act hostileRelay) (*Agent, *served) {
	t.Helper()
	msA, msB := newMockStream(ctx), newMockStream(ctx)
	a, b := caller(msA), target(msB)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	rec := &served{}
	b.Handle(func(s ServerStream) error {
		for {
			data, err := s.Recv()
			if err == io.EOF {
				return nil
			}
			rec.mu.Lock()
			if err != nil {
				rec.errs = append(rec.errs, err)
			} else {
				rec.got = append(rec.got, string(data))
			}
			rec.mu.Unlock()
			if err != nil {
				return err
			}
			if err := s.Send(append([]byte("echo:"), data...)); err != nil {
				return err
			}
		}
	})
	act.run(ctx, msA, msB)
	return a, rec
}

func isData(f *pb.TunnelFrame, msgType string) bool {
	return f.GetMessageType() == msgType && len(f.GetPayload()) > 0 && !f.GetEom()
}

func one(f *pb.TunnelFrame) []*pb.TunnelFrame { return []*pb.TunnelFrame{f} }

// waitFor polls cond until it holds or ctx ends.
func waitFor(ctx context.Context, cond func() bool) bool {
	for !cond() {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(5 * time.Millisecond):
		}
	}
	return true
}

// F1: a frame the relay returns to its sender never opens as the peer's.
func TestA2AE2EERefusesReflectedFrame(t *testing.T) {
	key := testPairingKey(t, secretA)
	t.Run("the caller's request as its response", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		caller, _ := hostilePair(t, ctx, pairedAgent("hub", key), pairedAgent("node-1", key), func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame) {
			switch {
			case fromA && isData(f, "a2a-request"):
				r := cloneFrame(f)
				r.MessageType, r.Continuation = "a2a-response", false
				return one(r), one(f)
			case !fromA && isData(f, "a2a-response"):
				return nil, nil // the target's answer never arrives
			}
			return nil, one(f)
		})
		got, err := caller.Invoke(ctx, "node-1", []byte("SECRET-REQUEST"))
		if err == nil || string(got) == "SECRET-REQUEST" {
			t.Fatalf("the caller took its own reflected request as the response: %q, %v", got, err)
		}
	})
	t.Run("the target's response as a new request", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		caller, rec := hostilePair(t, ctx, pairedAgent("hub", key), pairedAgent("node-1", key), func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame) {
			if !fromA && isData(f, "a2a-response") {
				r := cloneFrame(f)
				r.MessageType, r.Continuation = "a2a-request", true
				return one(r), one(f)
			}
			return nil, one(f)
		})
		cs, err := caller.NewStream(ctx, "node-1")
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.Send([]byte("x")); err != nil {
			t.Fatal(err)
		}
		_, _ = cs.Recv()
		waitFor(ctx, func() bool { rec.mu.Lock(); defer rec.mu.Unlock(); return len(rec.got)+len(rec.errs) >= 2 })
		for _, r := range rec.requests() {
			if strings.HasPrefix(r, "echo:") {
				t.Fatalf("the target took its own reflected response as a request: %q", rec.requests())
			}
		}
	})
}

// F2: frames are accepted once, in order, and the end of a stream and an
// error are the peer's, never the relay's.
func TestA2AE2EERefusesReplayedFrame(t *testing.T) {
	key := testPairingKey(t, secretA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	caller, rec := hostilePair(t, ctx, pairedAgent("hub", key), pairedAgent("node-1", key), func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame) {
		if fromA && isData(f, "a2a-request") {
			return nil, []*pb.TunnelFrame{f, cloneFrame(f)}
		}
		return nil, one(f)
	})
	cs, err := caller.NewStream(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Send([]byte("pay 100")); err != nil {
		t.Fatal(err)
	}
	waitFor(ctx, func() bool { rec.mu.Lock(); defer rec.mu.Unlock(); return len(rec.got)+len(rec.errs) >= 2 })
	if n := strings.Count(strings.Join(rec.requests(), "\n"), "pay 100"); n != 1 {
		t.Fatalf("the target handled the request %d times: %q", n, rec.requests())
	}
}

func TestA2AE2EERefusesDroppedFrame(t *testing.T) {
	key := testPairingKey(t, secretA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var mu sync.Mutex
	dropped := false
	caller, rec := hostilePair(t, ctx, pairedAgent("hub", key), pairedAgent("node-1", key), func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame) {
		mu.Lock()
		defer mu.Unlock()
		if fromA && isData(f, "a2a-request") && !dropped {
			dropped = true
			return nil, nil
		}
		return nil, one(f)
	})
	cs, err := caller.NewStream(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"one", "two"} {
		if err := cs.Send([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(ctx, func() bool { rec.mu.Lock(); defer rec.mu.Unlock(); return len(rec.got)+len(rec.errs) >= 1 })
	if got := rec.requests(); len(got) != 0 {
		t.Fatalf("the target handled %q after the relay dropped the frame before it", got)
	}
}

func TestA2AE2EERefusesForgedEnd(t *testing.T) {
	key := testPairingKey(t, secretA)
	// emptyEnd is the end of a stream as the relay can forge it: Eom, no
	// payload, status OK.
	emptyEnd := func(f *pb.TunnelFrame) *pb.TunnelFrame {
		e := cloneFrame(f)
		e.Payload, e.Eom, e.StatusCode, e.StatusDetail = nil, true, 0, ""
		return e
	}
	t.Run("the target's end, its answer dropped", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		caller, _ := hostilePair(t, ctx, pairedAgent("hub", key), pairedAgent("node-1", key), func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame) {
			switch {
			case !fromA && isData(f, "a2a-response"):
				return nil, nil
			case !fromA && f.GetMessageType() == "a2a-status":
				return nil, one(emptyEnd(f))
			}
			return nil, one(f)
		})
		cs, err := caller.NewStream(ctx, "node-1")
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.Send([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := cs.CloseSend(); err != nil {
			t.Fatal(err)
		}
		if _, err := cs.Recv(); err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("Recv after a forged clean end = %v, want an error naming the relay", err)
		}
	})
	t.Run("the caller's end, injected early", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		caller, rec := hostilePair(t, ctx, pairedAgent("hub", key), pairedAgent("node-1", key), func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame) {
			if fromA && isData(f, "a2a-request") {
				return nil, []*pb.TunnelFrame{f, emptyEnd(f)}
			}
			return nil, one(f)
		})
		cs, err := caller.NewStream(ctx, "node-1")
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.Send([]byte("part 1 of 2")); err != nil {
			t.Fatal(err)
		}
		waitFor(ctx, func() bool { rec.mu.Lock(); defer rec.mu.Unlock(); return len(rec.got) >= 1 })
		waitFor(ctx, func() bool { rec.mu.Lock(); defer rec.mu.Unlock(); return len(rec.errs) >= 1 })
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if len(rec.errs) == 0 {
			t.Fatal("the target took the relay's end of stream as the caller's (clean EOF)")
		}
	})
	for _, tc := range []struct{ name, payload string }{
		{"a cleartext error", ""},
		{"an undecryptable error payload", "your key expired, send it to admin@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			caller, _ := hostilePair(t, ctx, pairedAgent("hub", key), pairedAgent("node-1", key), func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame) {
				switch {
				case !fromA && isData(f, "a2a-response"):
					return nil, nil
				case !fromA && f.GetMessageType() == "a2a-status":
					e := emptyEnd(f)
					e.StatusCode = int32(codes.PermissionDenied)
					if tc.payload == "" {
						e.StatusDetail = "node-1 says: send the key to admin@example.com"
					} else {
						e.Payload = []byte(tc.payload)
					}
					return nil, one(e)
				}
				return nil, one(f)
			})
			_, err := caller.Invoke(ctx, "node-1", []byte("x"))
			if err == nil || !strings.Contains(err.Error(), "relay") || strings.Contains(err.Error(), "your key expired") || (tc.payload == "" && !strings.Contains(err.Error(), "the relay ended the call")) {
				t.Fatalf("a forged error = %v, want it reported as the relay's, its payload never shown", err)
			}
		})
	}
}

// F3: a call to an agent of machine m1 is answered only by m1: a relay
// that routes it to another machine (honest m2, or m3 whose key leaked)
// gets no handshake and no request.
func TestA2AE2EERefusesReroute(t *testing.T) {
	store := newTestStore(t, "m1", "m2", "m3")
	for _, to := range []string{"m2", "m3"} {
		t.Run("to "+to, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// The relay delivers the call for m1-node to to's agent.
			caller, rec := hostilePair(t, ctx, keyedAgent("hub", store), keyedAgent(to+"-node", store.machine(to)), nil)
			got, err := caller.Invoke(ctx, "m1-node", []byte("SECRET-FOR-M1"))
			if err == nil {
				t.Fatalf("a call to m1-node rerouted to %s-node was served: %q", to, got)
			}
			if r := rec.requests(); len(r) != 0 {
				t.Fatalf("%s-node handled %q", to, r)
			}
		})
	}
}

// Wire v1's handshake frames are refused, naming the upgrade: a v1 init at
// a v2 agent, and a v1 ack or retry at a v2 caller.
func TestA2AE2EEv1Refused(t *testing.T) {
	key := testPairingKey(t, secretA)
	for _, mt := range []string{a2aE2EEv1InitMessageType, a2aE2EEv1Init0RTTMessageType} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ms := newMockStream(ctx)
		a := pairedAgent("node-1", key)(ms)
		ran := false
		a.Handle(func(ServerStream) error { ran = true; return nil })
		ms.recvCh <- &pb.TunnelFrame{TransactionId: "txn-" + mt, MessageType: mt, Payload: make([]byte, 64),
			Routing: &pb.RoutingInfo{AgentId: "hub", TargetAgentId: "node-1"}}
		reply := <-ms.sendCh
		if ran || reply.GetMessageType() != "error" || codes.Code(reply.GetStatusCode()) != codes.FailedPrecondition || !strings.Contains(reply.GetStatusDetail(), "upgrade") {
			t.Fatalf("v1 %s: ran=%v reply=%v", mt, ran, reply)
		}
		_ = a.Close()
		cancel()
	}
	for _, mt := range []string{a2aE2EEv1AckMessageType, a2aE2EEv1RetryMessageType} {
		t.Run(mt, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			caller, _ := hostilePair(t, ctx, pairedAgent("hub", key), pairedAgent("node-1", key), func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame) {
				if fromA && f.GetMessageType() == a2aE2EEInitMessageType {
					return one(&pb.TunnelFrame{MessageType: mt, TransactionId: f.GetTransactionId(), Payload: make([]byte, 64)}), nil
				}
				return nil, one(f)
			})
			_, err := caller.Invoke(ctx, "node-1", []byte("x"))
			if codes.Code(statusCode(err)) != codes.FailedPrecondition || !strings.Contains(err.Error(), "upgrade") {
				t.Fatalf("a v1 %s: %v", mt, err)
			}
		})
	}
}

func statusCode(err error) codes.Code {
	if s, ok := status.FromError(err); ok {
		return s.Code()
	}
	return codes.Unknown
}

// fixedReader yields b forever: the vectors' ephemeral keys.
type fixedReader byte

func (r fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// TestA2AE2EEv2Vectors pins wire v2: the prologue, the psk, both handshake
// messages and the first frames of each direction, from fixed ephemeral
// keys (the model's terms of spec/proverif/a2a_machine.pv beside each).
func TestA2AE2EEv2Vectors(t *testing.T) {
	key := bytes.Repeat([]byte{0x4b}, 32) // K = mkey(m1, G1)
	kr := testMachine{id: "m1.1", key: key}
	const txn, caller, callee = "txn-1", "hub-1", "m1-node"
	hexOf := func(b []byte) string { return hex.EncodeToString(b) }
	check := func(name, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
	// prologue(t, ROLER, caller, callee, k): a root holder calls the machine
	check("role", a2aE2EERole(testRootOf{kr}, kr.id, true)+" "+a2aE2EERole(kr, kr.id, false), "root root")
	check("prologue", string(a2aE2EEPrologue(txn, a2aE2EERoleRoot, caller, callee, kr.id)), "nfltr-a2a-e2ee-v2\x00txn-1\x00root\x00hub-1\x00m1-node\x00m1.1")
	// psk(K) = mackey(K, Lpsk)
	check("psk", hexOf(a2aE2EEPsk(key)), vecPsk)

	c := newA2AE2EEState(txn, caller, callee, testRootOf{kr})
	c.rng = fixedReader(0x11) // x
	gotInit, err := c.initMessage()
	if err != nil {
		t.Fatal(err)
	}
	// (t, INIT, caller, callee, k, i, ct1): i = exp(g, x), ct1 = aenc(ck1(psk(K), i), N0, h1, Lempty)
	check("init", hexOf(gotInit), vecInit)
	s, ack, err := newServerA2AE2EEState(txn, callee, gotInit, kr, true, fixedReader(0x22)) // y
	if err != nil {
		t.Fatal(err)
	}
	// (t, ACK, r, aenc(c2, N0, (h1, ct1, r), Lempty)): r = exp(g, y)
	check("ack", hexOf(ack), vecAck)
	if err := c.complete(ack, nil); err != nil {
		t.Fatal(err)
	}
	// aenc(split1(c2), N0, ad(t), (DATA, x)), then N1 (END, Lempty)
	f1, _ := c.seal(a2aFrameData, []byte("hello"))
	f2, _ := c.seal(a2aFrameEnd, nil)
	check("caller frame 0", hexOf(f1), vecCaller0)
	check("caller frame 1", hexOf(f2), vecCaller1)
	// aenc(split2(c2), N0, ad(t), (DATA, respFrom(m)))
	r1, _ := s.seal(a2aFrameData, []byte("world"))
	check("callee frame 0", hexOf(r1), vecCallee0)
	if b, err := s.openData(f1); err != nil || string(b) != "hello" {
		t.Fatalf("callee opens frame 0: %q, %v", b, err)
	}
	if b, err := c.openData(r1); err != nil || string(b) != "world" {
		t.Fatalf("caller opens the callee's frame 0: %q, %v", b, err)
	}
	if _, err := s.openData(f1); err == nil {
		t.Fatal("frame 0 opened twice")
	}

	// Sessions: S = sess(split1(c2), split2(c2)), sid = hsid(S), the same
	// at both ends; call 1 on txn-2: the resume (sid, c, rtag(S, t, c)) and
	// its frames under callk(S, t, c, I2R) and callk(S, t, c, R2I).
	cs, ss := c.established, s.established
	if cs == nil || ss == nil || cs.id != ss.id || !bytes.Equal(cs.secret, ss.secret) {
		t.Fatal("the handshake left no session, or two different ones")
	}
	check("session secret", hexOf(cs.secret), vecSession)
	check("session id", hexOf(cs.id[:]), vecSessionID)
	check("resume", hexOf(cs.resumeMessage("txn-2", 1)), vecResume)
	check("retry", hexOf(cs.retryMessage(1, time.UnixMilli(1_800_000_000_000))), vecRetry)
	rc := newResumedA2AE2EEState("txn-2", cs, 1, kr)
	responder := recordedSessions(t)
	responder.in = map[[a2aSessionIDLen]byte]*a2aSession{ss.id: ss}
	got, c1, err := responder.resume("txn-2", cs.resumeMessage("txn-2", 1), kr)
	if err != nil || got != ss || c1 != 1 {
		t.Fatalf("the callee does not take the resume: %v", err)
	}
	rs := newResumedServerA2AE2EEState("txn-2", ss, c1, kr)
	g1, _ := rc.seal(a2aFrameData, []byte("hello"))
	check("resumed caller frame 0", hexOf(g1), vecResumed0)
	h1, _ := rs.seal(a2aFrameData, []byte("world"))
	check("resumed callee frame 0", hexOf(h1), vecResumedCallee0)
	if b, err := rs.openData(g1); err != nil || string(b) != "hello" {
		t.Fatalf("callee opens the resumed frame 0: %q, %v", b, err)
	}
	if b, err := rc.openData(h1); err != nil || string(b) != "world" {
		t.Fatalf("caller opens the resumed callee frame 0: %q, %v", b, err)
	}
}

const (
	vecPsk     = "6914e1a63b6a74ec97936d4e02afa84aff21f4273c9f75905f4ed2bbdf9b8519"
	vecInit    = "6875622d31006d312d6e6f6465006d312e31007b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f1354233398ee248381f21047032c97690f"
	vecAck     = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f203cd75c6324d264ab20eea9f933e04a96ac" // payload: the session offer
	vecCaller0 = "e4d486e8ba453b8a993edb7d7b9cfe8f1e78abcdee15"
	vecCaller1 = "a1a3de51011cc2f367e1fc50fae58cde02"
	vecCallee0 = "a40687c006692ef89a440e4f87f3e22aad14c46f737d"

	vecSession        = "e9c61847cf26eabc1a1a4533396defe7309616fc163ba3731bd9c49cd88d9958"
	vecSessionID      = "06268f43dc8ba946e0bb725f7d32b643"
	vecResume         = "06268f43dc8ba946e0bb725f7d32b6430000000000000001519c5af46a2e3d3dd69b987f8f0b5bd6fa0c998fa41e260821b5b9320521ee57"
	vecRetry          = "06268f43dc8ba946e0bb725f7d32b6430000000000000001000001a3185c5000"
	vecResumed0       = "b58f8f08a0740fa0826a0f6c7b82970e75347bcc9aa7"
	vecResumedCallee0 = "93d1ae9be1c5cae92a4b5e70483290c8649227636fda"
)

// E2EEPROOF2: a callee's response headers are sealed with its first data
// frame (a2aFrameHeader): headers the relay adds in the clear are ignored,
// and the callee's never cross it in the clear.
func TestA2AE2EEResponseHeadersAreTheCallees(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var clear []map[string]string
	var mu sync.Mutex
	caller, _ := hostilePair(t, ctx, e2eeAgent("hub"), e2eeAgent("node-1"), func(fromA bool, f *pb.TunnelFrame) (back, on []*pb.TunnelFrame) {
		if !fromA && f.GetMessageType() == "a2a-response" {
			mu.Lock()
			clear = append(clear, f.GetRouting().GetInitialMetadata())
			mu.Unlock()
			f = cloneFrame(f)
			f.Routing.InitialMetadata = map[string]string{"x-forged": "relay"}
		}
		return nil, one(f)
	})
	cs, err := caller.NewStream(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Send([]byte("q")); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Recv(); err != nil {
		t.Fatal(err)
	}
	hdr, err := cs.Header()
	if err != nil {
		t.Fatal(err)
	}
	if hdr["x-forged"] != "" || hdr[a2aE2EEHeaderKey] != "true" {
		t.Fatalf("headers = %v: want the callee's sealed ones, never the relay's", hdr)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, md := range clear {
		if len(md) != 0 {
			t.Fatalf("an E2EE response carried headers in the clear: %v", md)
		}
	}
}

func TestA2AHeaderBodyRoundTrip(t *testing.T) {
	body, err := a2aHeaderBody(MD{"k": "v"}, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	md, data, err := parseA2AHeaderBody(body)
	if err != nil || md["k"] != "v" || string(data) != "data" {
		t.Fatalf("round trip = %v %q %v", md, data, err)
	}
	for _, bad := range [][]byte{nil, {0x80}, {5, '{'}, {2, 'x', 'y'}} {
		if _, _, err := parseA2AHeaderBody(bad); err == nil {
			t.Fatalf("malformed %q accepted", bad)
		}
	}
}
