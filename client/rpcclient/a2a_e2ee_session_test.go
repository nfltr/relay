// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// A2A E2EE sessions (a2a_e2ee_session.go): one test per query and mutant
// of spec/proverif/a2a_machine.pv "Sessions" and per invariant of
// spec/A2ASession.tla, against a relay that replays, splices, reroutes and
// forges.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// frameLog counts the frames a relay saw, by message type and side.
type frameLog struct {
	mu   sync.Mutex
	from map[bool]map[string]int
}

func (l *frameLog) add(fromA bool, f *pb.TunnelFrame) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.from == nil {
		l.from = map[bool]map[string]int{true: {}, false: {}}
	}
	l.from[fromA][f.GetMessageType()]++
}

func (l *frameLog) count(fromA bool, msgType string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.from[fromA][msgType]
}

func countingRelay(l *frameLog, next hostileRelay) hostileRelay {
	return func(fromA bool, f *pb.TunnelFrame) ([]*pb.TunnelFrame, []*pb.TunnelFrame) {
		l.add(fromA, f)
		if next == nil {
			return nil, one(f)
		}
		return next(fromA, f)
	}
}

// awaitEnded waits until b no longer serves txn (its handler returned
// after the caller had its answer): a frame of txn replayed earlier is
// dropped as a second start of a served call, not answered.
func awaitEnded(t *testing.T, ctx context.Context, b *Agent, txn string) {
	t.Helper()
	if !waitFor(ctx, func() bool { _, serving := b.incoming.Load(txn); return !serving }) {
		t.Fatalf("txn %s still served", txn)
	}
}

// restartSessions is a callee's restart, as far as its sessions go: it
// loses them (spec/A2ASession.tla Restart).
func restartSessions(b *Agent) {
	b.sessions.mu.Lock()
	b.sessions.in = nil
	b.sessions.mu.Unlock()
	traceAS("Restart", "", b.ref, "", nil, 0, nil)
}

func invokeCtx(t *testing.T, caller *Agent, target, req string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return caller.Invoke(ctx, target, []byte(req))
}

// The first call between a pair handshakes; every later one resumes its
// session: one init, then resumes only, in both directions.
func TestA2AE2EESessionReused(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var log frameLog
	caller, rec := hostilePair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", store.machine("m1")), countingRelay(&log, nil))
	for i := range 5 {
		if got, err := invokeCtx(t, caller, "m1-node", "q"); err != nil || string(got) != "echo:q" {
			t.Fatalf("call %d = %q, %v", i, got, err)
		}
	}
	if n, r := log.count(true, a2aE2EEInitMessageType), log.count(true, a2aE2EEResumeMessageType); n != 1 || r != 4 {
		t.Fatalf("inits %d, resumes %d; want 1 and 4", n, r)
	}
	if n := len(rec.requests()); n != 5 {
		t.Fatalf("handled %d requests, want 5", n)
	}
}

// Latency guard: a resumed call sends its request before it hears anything
// from the callee (no round trip before it), and over a relay with a
// round trip of rtt it takes one rtt less than the first call.
func TestA2AE2EEResumedCallSkipsARoundTrip(t *testing.T) {
	store := newTestStore(t, "m1")
	const rtt = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	msA, msB := newMockStream(ctx), newMockStream(ctx)
	a, b := keyedAgent("hub", store)(msA), keyedAgent("m1-node", store.machine("m1"))(msB)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	b.Handle(func(s ServerStream) error {
		data, err := s.Recv()
		if err != nil {
			return err
		}
		return s.Send(append([]byte("echo:"), data...))
	})
	// Each direction delivers in order, rtt/2 after the frame was sent.
	var mu sync.Mutex
	var order [][2]string // {"A:<type>" / "B:<type>", txn} as delivered
	delay := func(from, to *mockStream, side string) {
		q := make(chan struct {
			f  *pb.TunnelFrame
			at time.Time
		}, 1024)
		go func() {
			for {
				select {
				case f := <-from.sendCh:
					q <- struct {
						f  *pb.TunnelFrame
						at time.Time
					}{f, time.Now().Add(rtt / 2)}
				case <-ctx.Done():
					return
				}
			}
		}()
		go func() {
			for {
				select {
				case e := <-q:
					time.Sleep(time.Until(e.at))
					mu.Lock()
					order = append(order, [2]string{side + ":" + e.f.GetMessageType(), e.f.GetTransactionId()})
					mu.Unlock()
					select {
					case to.recvCh <- e.f:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	delay(msA, msB, "A")
	delay(msB, msA, "B")
	// call runs one call and returns its frames (by the txn of its first
	// frame of type first) in delivery order; the previous call's trailer
	// may still be in flight, so frames are matched by txn.
	call := func(first string) []string {
		mu.Lock()
		order = nil
		mu.Unlock()
		if got, err := a.Invoke(ctx, "m1-node", []byte("q")); err != nil || string(got) != "echo:q" {
			t.Fatalf("Invoke = %q, %v", got, err)
		}
		mu.Lock()
		defer mu.Unlock()
		var txn string
		var calls []string
		for _, e := range order {
			if txn == "" && e[0] == "A:"+first {
				txn = e[1]
			}
			if txn != "" && e[1] == txn {
				calls = append(calls, e[0])
			}
		}
		return calls
	}
	// roundTrips counts the caller's turns: each run of caller frames that
	// the callee answers is one round trip. Counted, not timed, so a
	// loaded machine cannot fail it.
	roundTrips := func(calls []string) int {
		n := 0
		for i, c := range calls {
			if strings.HasPrefix(c, "B:") && (i == 0 || strings.HasPrefix(calls[i-1], "A:")) {
				n++
			}
		}
		return n
	}
	firstCall := call(a2aE2EEInitMessageType)
	second := call(a2aE2EEResumeMessageType)
	// The resume and the request reach the callee before any frame of the
	// callee's reaches the caller.
	if len(second) < 2 || second[0] != "A:"+a2aE2EEResumeMessageType || second[1] != "A:a2a-request" {
		t.Fatalf("second call's frames in delivery order %q: want the resume, then the request, first", second)
	}
	if f, s := roundTrips(firstCall), roundTrips(second); s != 1 || f != s+1 {
		t.Fatalf("round trips: first call %d %q, resumed call %d %q: want the resumed one a single round trip, one fewer", f, firstCall, s, second)
	}
}

// Query 14, mutant sess-unbound: a session is its pair's. Two agents of
// one machine share its key; a relay that delivers every call to m1-a
// gets a call for m1-b served nowhere: the caller has no session with
// m1-b, and m1-a refuses a handshake that names m1-b.
func TestA2AE2EESessionBoundToPair(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	caller, _, _, _, rec := relayPair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-a", store.machine("m1")), nil)
	if _, err := invokeCtx(t, caller, "m1-a", "for a"); err != nil {
		t.Fatal(err)
	}
	if got, err := invokeCtx(t, caller, "m1-b", "SECRET-FOR-B"); err == nil {
		t.Fatalf("a call for m1-b delivered to m1-a was served: %q", got)
	}
	if got := rec.requests(); len(got) != 1 {
		t.Fatalf("m1-a served %q", got)
	}
}

// Queries 16-18, mutant txn-unbound: a resumed call's frames are its own.
// A relay that delivers call A's resume and frames as another call (a new
// txn) gets nothing served; one that splices a frame of call A into call
// B ends call B.
func TestA2AE2EEResumedFrameNotInAnotherCall(t *testing.T) {
	store := newTestStore(t, "m1")
	t.Run("as a new call", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var log frameLog
		caller, rec := hostilePair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", store.machine("m1")), countingRelay(&log, func(fromA bool, f *pb.TunnelFrame) ([]*pb.TunnelFrame, []*pb.TunnelFrame) {
			if fromA && log.count(true, a2aE2EEResumeMessageType) > 0 && (f.GetMessageType() == a2aE2EEResumeMessageType || isData(f, "a2a-request")) {
				g := cloneFrame(f)
				g.TransactionId = "spliced-" + f.GetTransactionId()
				return nil, []*pb.TunnelFrame{g, f}
			}
			return nil, one(f)
		}))
		if _, err := invokeCtx(t, caller, "m1-node", "one"); err != nil {
			t.Fatal(err)
		}
		if _, err := invokeCtx(t, caller, "m1-node", "pay 100"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		if got := rec.requests(); len(got) != 2 {
			t.Fatalf("handled %q: the spliced call was served", got)
		}
	})
	t.Run("into another call", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var mu sync.Mutex
		var resumes int
		var callA *pb.TunnelFrame
		caller, rec := hostilePair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", store.machine("m1")), func(fromA bool, f *pb.TunnelFrame) ([]*pb.TunnelFrame, []*pb.TunnelFrame) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case fromA && f.GetMessageType() == a2aE2EEResumeMessageType:
				resumes++
			case fromA && isData(f, "a2a-request") && resumes == 1:
				callA = cloneFrame(f)
			case fromA && isData(f, "a2a-request") && resumes == 2:
				g := cloneFrame(callA)
				g.TransactionId = f.GetTransactionId()
				return nil, one(g) // call A's frame in place of call B's
			}
			return nil, one(f)
		})
		for _, req := range []string{"H", "A"} {
			if _, err := invokeCtx(t, caller, "m1-node", req); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := invokeCtx(t, caller, "m1-node", "B"); err == nil {
			t.Fatalf("call B with call A's frame = %q", got)
		}
		if got := rec.requests(); len(got) != 2 || got[1] != "A" {
			t.Fatalf("served %q: call A's request served in call B", got)
		}
	})
}

// relayPair is hostilePair with the target and the streams at hand.
func relayPair(t *testing.T, ctx context.Context, caller, target func(AgentTunnel) *Agent, act hostileRelay) (a, b *Agent, msA, msB *mockStream, rec *served) {
	t.Helper()
	msA, msB = newMockStream(ctx), newMockStream(ctx)
	a, b = caller(msA), target(msB)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	rec = &served{}
	b.Handle(func(s ServerStream) error {
		d, err := s.Recv()
		if err != nil {
			return err
		}
		rec.mu.Lock()
		rec.got = append(rec.got, string(d))
		rec.mu.Unlock()
		return s.Send(append([]byte("echo:"), d...))
	})
	act.run(ctx, msA, msB)
	return a, b, msA, msB, rec
}

// spec/A2ASession.tla AtMostOnce: a relay that replays a resumed call
// (its resume and its request) gets it served once; the callee answers
// the replay unknown.
func TestA2AE2EEResumedCallReplayRefused(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var resumed []*pb.TunnelFrame
	var log frameLog
	caller, b, _, msB, rec := relayPair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", store.machine("m1")), countingRelay(&log, func(fromA bool, f *pb.TunnelFrame) ([]*pb.TunnelFrame, []*pb.TunnelFrame) {
		mu.Lock()
		defer mu.Unlock()
		if fromA && (f.GetMessageType() == a2aE2EEResumeMessageType || (len(resumed) > 0 && isData(f, "a2a-request"))) {
			resumed = append(resumed, cloneFrame(f))
		}
		return nil, one(f)
	}))
	for _, req := range []string{"one", "pay 100"} {
		if _, err := invokeCtx(t, caller, "m1-node", req); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	frames := append([]*pb.TunnelFrame(nil), resumed...)
	mu.Unlock()
	if len(frames) != 2 {
		t.Fatalf("recorded %d frames of the resumed call", len(frames))
	}
	awaitEnded(t, ctx, b, frames[0].GetTransactionId())
	for _, f := range frames {
		msB.recvCh <- cloneFrame(f)
	}
	if !waitFor(ctx, func() bool { return log.count(false, a2aE2EEUnknownMessageType) == 1 }) {
		t.Fatal("the replayed resume was not answered unknown")
	}
	if got := rec.requests(); len(got) != 2 {
		t.Fatalf("served %q: the replay was served", got)
	}
}

// Unit form of the window: each call number once, none at or below the
// window's floor.
func TestA2AE2EESessionWindow(t *testing.T) {
	s := &a2aSession{}
	if s.takeCallNumber(0) {
		t.Fatal("call number 0 (the handshake's) taken")
	}
	for _, c := range []uint64{1, 3, 2} {
		if !s.takeCallNumber(c) {
			t.Fatalf("fresh %d refused", c)
		}
	}
	if s.takeCallNumber(2) {
		t.Fatal("2 taken twice")
	}
	if !s.takeCallNumber(1 + a2aReplayWindow + 5) {
		t.Fatal("a jump ahead refused")
	}
	if s.takeCallNumber(4) {
		t.Fatal("4, below the floor, taken")
	}
	if len(s.seen) > a2aReplayWindow {
		t.Fatalf("window holds %d numbers", len(s.seen))
	}
}

// Query 15, mutant counter-reset: no key is used by two calls: the keys
// differ by call number and by txn, so the same request in two calls
// seals to different frames.
func TestA2AE2EECallKeysUnique(t *testing.T) {
	s := &a2aSession{secret: bytes.Repeat([]byte{7}, 32)}
	seal := func(txn string, c uint64) []byte {
		i2r, _ := s.callKeys(txn, c)
		ct, err := i2r.Encrypt(nil, []byte(txn), []byte{a2aFrameData, 'x'})
		if err != nil {
			t.Fatal(err)
		}
		return ct[:len(ct)-16]
	}
	if bytes.Equal(seal("t1", 1), seal("t1", 2)) || bytes.Equal(seal("t1", 1), seal("t2", 1)) {
		t.Fatal("two calls share a key")
	}
	i2r, r2i := s.callKeys("t1", 1)
	a, _ := i2r.Encrypt(nil, nil, []byte("x"))
	b, _ := r2i.Encrypt(nil, nil, []byte("x"))
	if bytes.Equal(a, b) {
		t.Fatal("both directions share a key")
	}
}

// Query 13, mutant survive-revoke: a revoke ends the session: the caller
// handshakes (and For refuses it), the callee answers a resume of the
// revoked key unknown.
func TestA2AE2EERevokeEndsSession(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var log frameLog
	caller, _ := hostilePair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", store.machine("m1")), countingRelay(&log, nil))
	if _, err := invokeCtx(t, caller, "m1-node", "one"); err != nil {
		t.Fatal(err)
	}
	store.revoke("m1")
	if got, err := invokeCtx(t, caller, "m1-node", "two"); err == nil {
		t.Fatalf("a call to a revoked machine = %q", got)
	}
	if log.count(true, a2aE2EEResumeMessageType) != 0 {
		t.Fatal("the caller resumed a revoked machine's session")
	}
	if caller.sessions.out["m1-node"] != nil {
		t.Fatal("the caller kept a revoked machine's session")
	}
	// The callee side: a root holder answering a revoked machine.
	m := newTestStore(t, "m1")
	mach, root, _, _, _ := relayPair(t, ctx, keyedAgent("m1-node", m.machine("m1")), keyedAgent("hub", m), nil)
	if _, err := invokeCtx(t, mach, "hub", "one"); err != nil {
		t.Fatal(err)
	}
	m.revoke("m1")
	if got, err := invokeCtx(t, mach, "hub", "two"); err == nil {
		t.Fatalf("the root holder served a revoked machine's resumed call: %q", got)
	}
	root.sessions.mu.Lock()
	defer root.sessions.mu.Unlock()
	if len(root.sessions.in) != 0 {
		t.Fatal("the root holder kept a revoked machine's session")
	}
}

// A rotation (the machine key's generation) rekeys: the session of the old
// key is dropped, the next call handshakes under the new one.
func TestA2AE2EERotationRekeys(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var log frameLog
	var mach atomic.Pointer[A2AE2EEKeyring]
	k := store.machine("m1")
	mach.Store(&k)
	caller, _ := hostilePair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", swapKeyring{&mach}), countingRelay(&log, nil))
	if _, err := invokeCtx(t, caller, "m1-node", "one"); err != nil {
		t.Fatal(err)
	}
	store.rotate("m1")
	k2 := store.machine("m1")
	mach.Store(&k2)
	if _, err := invokeCtx(t, caller, "m1-node", "two"); err != nil {
		t.Fatal(err)
	}
	if n, r := log.count(true, a2aE2EEInitMessageType), log.count(true, a2aE2EEResumeMessageType); n != 2 || r != 0 {
		t.Fatalf("inits %d, resumes %d after a rotation; want 2 and 0", n, r)
	}
}

// swapKeyring is a machine's key file, replaced in place by a rotation.
type swapKeyring struct {
	p *atomic.Pointer[A2AE2EEKeyring]
}

func (k swapKeyring) For(ref string) (string, []byte, error) { return (*k.p.Load()).For(ref) }
func (k swapKeyring) Valid(id string) bool                   { return (*k.p.Load()).Valid(id) }
func (k swapKeyring) Machine() bool                          { return (*k.p.Load()).Machine() }

// A responder restart (it lost its sessions): the resume is answered
// unknown, the caller handshakes once on the same call and sends its
// request again; served once, never in plaintext.
func TestA2AE2EEResponderRestartRehandshakes(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var log frameLog
	msA, msB := newMockStream(ctx), newMockStream(ctx)
	a, b := keyedAgent("hub", store)(msA), keyedAgent("m1-node", store.machine("m1"))(msB)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	rec := &served{}
	b.Handle(func(s ServerStream) error {
		d, err := s.Recv()
		if err != nil {
			return err
		}
		rec.mu.Lock()
		rec.got = append(rec.got, string(d))
		rec.mu.Unlock()
		return s.Send(append([]byte("echo:"), d...))
	})
	hostileRelay(countingRelay(&log, func(fromA bool, f *pb.TunnelFrame) ([]*pb.TunnelFrame, []*pb.TunnelFrame) {
		if fromA && f.GetMessageType() == "a2a-request" && bytes.Contains(f.GetPayload(), []byte("SECRET")) {
			t.Errorf("a request in plaintext: %q", f.GetPayload())
		}
		return nil, one(f)
	})).run(ctx, msA, msB)
	if _, err := invokeCtx(t, a, "m1-node", "one"); err != nil {
		t.Fatal(err)
	}
	restartSessions(b)
	if got, err := invokeCtx(t, a, "m1-node", "SECRET two"); err != nil || string(got) != "echo:SECRET two" {
		t.Fatalf("after the responder's restart = %q, %v", got, err)
	}
	if n, r, u := log.count(true, a2aE2EEInitMessageType), log.count(true, a2aE2EEResumeMessageType), log.count(false, a2aE2EEUnknownMessageType); n != 2 || r != 1 || u != 1 {
		t.Fatalf("inits %d, resumes %d, unknowns %d; want 2, 1, 1", n, r, u)
	}
	if got := rec.requests(); len(got) != 2 {
		t.Fatalf("served %q", got)
	}
	// The handshake left a new session: the next call resumes it.
	if _, err := invokeCtx(t, a, "m1-node", "three"); err != nil || log.count(true, a2aE2EEResumeMessageType) != 2 {
		t.Fatalf("third call: %v, resumes %d", err, log.count(true, a2aE2EEResumeMessageType))
	}
}

// A relay's forged refusals: one in place of the callee's resumed makes
// the caller handshake (the callee, serving the call, drops that init: the
// call fails), one after the handshake ends the call; at most one
// handshake per call, never a plaintext or v1 frame.
func TestA2AE2EEForgedUnknownEndsCall(t *testing.T) {
	store := newTestStore(t, "m1")
	for _, tc := range []struct {
		name    string
		restart bool // the callee lost its sessions: its unknown is real
	}{{"in place of resumed", false}, {"after the handshake", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var log frameLog
			var armed atomic.Bool
			caller, b, _, _, rec := relayPair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", store.machine("m1")), countingRelay(&log, func(fromA bool, f *pb.TunnelFrame) ([]*pb.TunnelFrame, []*pb.TunnelFrame) {
				if fromA && f.GetMessageType() != a2aE2EEInitMessageType && f.GetMessageType() != a2aE2EEResumeMessageType && f.GetMessageType() != "cancel" && bytes.Contains(f.GetPayload(), []byte("SECRET")) {
					t.Errorf("a request in plaintext: %q", f.GetPayload())
				}
				if fromA && (f.GetMessageType() == a2aE2EEv1InitMessageType || f.GetMessageType() == a2aE2EEv1Init0RTTMessageType) {
					t.Errorf("a v1 init")
				}
				if !fromA && armed.Load() {
					switch {
					case !tc.restart && f.GetMessageType() == a2aE2EEResumedMessageType:
						g := cloneFrame(f)
						g.MessageType = a2aE2EEUnknownMessageType
						return nil, one(g)
					case tc.restart && f.GetMessageType() == a2aE2EEAckMessageType:
						return nil, []*pb.TunnelFrame{f, {MessageType: a2aE2EEUnknownMessageType, TransactionId: f.GetTransactionId()}}
					}
				}
				return nil, one(f)
			}))
			if _, err := invokeCtx(t, caller, "m1-node", "one"); err != nil {
				t.Fatal(err)
			}
			if tc.restart {
				restartSessions(b)
			}
			armed.Store(true)
			inits := log.count(true, a2aE2EEInitMessageType)
			cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
			defer ccancel()
			got, err := caller.Invoke(cctx, "m1-node", []byte("SECRET two"))
			if !tc.restart && err == nil {
				t.Fatalf("a call whose resumed the relay forged = %q", got)
			}
			if n := log.count(true, a2aE2EEInitMessageType) - inits; n > 1 {
				t.Fatalf("%d handshakes in one call", n)
			}
			// The call runs at most once: the retry the forged unknown
			// caused is dropped (the callee serves the call), not run
			// again (spec/A2ASession.tla AtMostOnce). Zero runs when the
			// forged unknown came before the caller sent its request: the
			// retry then holds the send until the call fails.
			if n := strings.Count(strings.Join(rec.requests(), "|"), "SECRET two"); n > 1 {
				t.Fatalf("the call ran %d times (requests %q)", n, rec.requests())
			}
		})
	}
}

// The relay holds a resume and its request, answers the caller unknown
// itself, and delivers them after the caller's retry ran the call: the
// retry took the call number, so the late resume is refused
// (spec/A2ASession.tla Unknown; mutant AS:retry-no-take).
func TestA2AE2EELateResumeAfterRetryRefused(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var held []*pb.TunnelFrame
	var armed atomic.Bool
	var log frameLog
	var msA, msB *mockStream // msA: set before any frame flows
	var caller *Agent
	var rec *served
	var b *Agent
	caller, b, msA, msB, rec = relayPair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", store.machine("m1")), countingRelay(&log, func(fromA bool, f *pb.TunnelFrame) ([]*pb.TunnelFrame, []*pb.TunnelFrame) {
		mu.Lock()
		defer mu.Unlock()
		if fromA && armed.Load() && (f.GetMessageType() == a2aE2EEResumeMessageType || (len(held) > 0 && len(held) < 2 && isData(f, "a2a-request"))) {
			held = append(held, cloneFrame(f))
			if len(held) == 2 { // the resume and the request, both sealed under the session
				msA.recvCh <- &pb.TunnelFrame{MessageType: a2aE2EEUnknownMessageType, TransactionId: f.GetTransactionId()}
			}
			return nil, nil
		}
		return nil, one(f)
	}))
	if _, err := invokeCtx(t, caller, "m1-node", "one"); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	if _, err := invokeCtx(t, caller, "m1-node", "pay 100"); err != nil {
		t.Fatalf("the retry after the relay's unknown: %v", err)
	}
	armed.Store(false)
	mu.Lock()
	frames := append([]*pb.TunnelFrame(nil), held...)
	mu.Unlock()
	if len(frames) != 2 {
		t.Fatalf("held %d frames of the resumed call, want 2", len(frames))
	}
	awaitEnded(t, ctx, b, frames[0].GetTransactionId())
	unknowns := log.count(false, a2aE2EEUnknownMessageType)
	for _, f := range frames {
		msB.recvCh <- cloneFrame(f)
	}
	if !waitFor(ctx, func() bool { return log.count(false, a2aE2EEUnknownMessageType) == unknowns+1 }) {
		t.Fatal("the late resume was not answered unknown")
	}
	if got := rec.requests(); len(got) != 2 {
		t.Fatalf("served %q, want each call once", got)
	}
}

// A retry is refused past its bound, for another pair's session, and for
// a call number its session took; a retry of a session the callee does
// not keep (a restart) is answered (spec/A2ASession.tla RetryOK).
func TestA2AE2EERetryChecks(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ss := &a2aSessions{now: func() time.Time { return now }}
	s := &a2aSession{id: [a2aSessionIDLen]byte{1}, caller: "hub", kid: "m1.1"}
	ss.in = map[[a2aSessionIDLen]byte]*a2aSession{s.id: s}
	gone := &a2aSession{id: [a2aSessionIDLen]byte{2}}
	for _, tc := range []struct {
		name        string
		msg         []byte
		caller, kid string
		ok          bool
	}{
		{"fresh", s.retryMessage(1, now), "hub", "m1.1", true},
		{"its number taken", s.retryMessage(1, now), "hub", "m1.1", false},
		{"past the bound", s.retryMessage(2, now.Add(-a2aRetryBound-time.Second)), "hub", "m1.1", false},
		{"ahead past the bound", s.retryMessage(2, now.Add(a2aRetryBound+time.Second)), "hub", "m1.1", false},
		{"another caller's session", s.retryMessage(3, now), "hub-b", "m1.1", false},
		{"another key's session", s.retryMessage(3, now), "hub", "m1.2", false},
		{"a session lost to a restart", gone.retryMessage(1, now), "hub", "m1.1", true},
		{"malformed", []byte{1, 2, 3}, "hub", "m1.1", false},
	} {
		if err := ss.retry(tc.msg, tc.caller, tc.kid); (err == nil) != tc.ok {
			t.Errorf("%s: retry = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}

// A2AWARM: a warm handshakes with no call (the callee runs no handler),
// and the first call after it resumes; a second warm is a no-op.
func TestA2AE2EEWarmLeavesASessionAndNoCall(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var log frameLog
	caller, rec := hostilePair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", store.machine("m1")), countingRelay(&log, nil))
	for range 2 {
		if err := caller.WarmA2AE2EE(ctx, "m1-node"); err != nil {
			t.Fatalf("warm: %v", err)
		}
	}
	if n := len(rec.requests()); n != 0 {
		t.Fatalf("a warm ran the handler: %d requests", n)
	}
	if got, err := invokeCtx(t, caller, "m1-node", "q"); err != nil || string(got) != "echo:q" {
		t.Fatalf("call after the warm = %q, %v", got, err)
	}
	if w, n, r := log.count(true, a2aE2EEWarmMessageType), log.count(true, a2aE2EEInitMessageType), log.count(true, a2aE2EEResumeMessageType); w != 1 || n != 0 || r != 1 {
		t.Fatalf("warms %d, inits %d, resumes %d; want 1, 0 and 1", w, n, r)
	}
	if err := NewAgent("plain", newMockStream(ctx)).WarmA2AE2EE(ctx, "m1-node"); !errors.Is(err, ErrA2AE2EENoKey) {
		t.Fatalf("warm without keys: %v", err)
	}
}

// Message 1 says whether it is a warm: a relay that retags a warm as a
// call's init, or an init as a warm, is refused by the callee before any
// handler or session (model a2a_machine.pv, mutant warm-untyped).
func TestA2AE2EEWarmRetagRefused(t *testing.T) {
	store := newTestStore(t, "m1")
	for _, tc := range []struct{ from, to string }{
		{a2aE2EEWarmMessageType, a2aE2EEInitMessageType},
		{a2aE2EEInitMessageType, a2aE2EEWarmMessageType},
	} {
		t.Run(tc.from, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			caller, rec := hostilePair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", store.machine("m1")),
				func(fromA bool, f *pb.TunnelFrame) ([]*pb.TunnelFrame, []*pb.TunnelFrame) {
					if fromA && f.GetMessageType() == tc.from {
						f.MessageType = tc.to
					}
					return nil, one(f)
				})
			var err error
			if tc.from == a2aE2EEWarmMessageType {
				err = caller.WarmA2AE2EE(ctx, "m1-node")
			} else {
				_, err = invokeCtx(t, caller, "m1-node", "q")
			}
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "retagged") {
				t.Fatalf("retagged %s: %v", tc.from, err)
			}
			if got := rec.requests(); len(got) != 0 {
				t.Fatalf("served %q", got)
			}
		})
	}
}

// A rotation while a resumed call waits for its resumed: the callee served
// the call and dropped the session of the old key; an unknown the relay
// forges then must not make the caller retry under the new key (the
// callee, keeping no session, would answer the retry and serve the call
// again). The caller ends a call whose key no longer holds instead of
// retrying it (spec/README.md finding S2; TraceA2ASession.tla rejected
// this run's trace: a session dropped within the retry bound, then a
// retry answered).
func TestA2AE2EERotationDoesNotRetryAServedCall(t *testing.T) {
	store := newTestStore(t, "m1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mach atomic.Pointer[A2AE2EEKeyring]
	k := store.machine("m1")
	mach.Store(&k)
	var armed atomic.Bool
	var txn atomic.Value
	caller, b, msA, _, rec := relayPair(t, ctx, keyedAgent("hub", store), keyedAgent("m1-node", swapKeyring{&mach}), func(fromA bool, f *pb.TunnelFrame) ([]*pb.TunnelFrame, []*pb.TunnelFrame) {
		if armed.Load() && fromA && f.GetMessageType() == a2aE2EEResumeMessageType {
			txn.Store(f.GetTransactionId())
		}
		if armed.Load() && !fromA && f.GetTransactionId() == txn.Load() {
			return nil, nil // the callee's resumed and answer: held
		}
		return nil, one(f)
	})
	if _, err := invokeCtx(t, caller, "m1-node", "one"); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	done := make(chan error, 1)
	go func() {
		cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
		defer ccancel()
		_, err := caller.Invoke(cctx, "m1-node", []byte("pay 100"))
		done <- err
	}()
	if !waitFor(ctx, func() bool { return len(rec.requests()) == 2 }) {
		t.Fatal("the resumed call was not served")
	}
	id, _ := txn.Load().(string)
	awaitEnded(t, ctx, b, id)
	store.rotate("m1")
	k2 := store.machine("m1")
	mach.Store(&k2)
	b.RecheckA2AE2EE() // the callee drops the old key's session
	armed.Store(false)
	msA.recvCh <- &pb.TunnelFrame{MessageType: a2aE2EEUnknownMessageType, TransactionId: id}
	if err := <-done; err == nil {
		t.Fatal("a call whose resumed the relay held succeeded")
	}
	if got := rec.requests(); len(got) != 2 {
		t.Fatalf("served %q: the call ran twice", got)
	}
}
