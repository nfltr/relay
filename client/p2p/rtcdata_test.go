// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/client/rpcclient"
	"github.com/nfltr/relay/proto/pb"
	"github.com/pion/webrtc/v4"
	"google.golang.org/protobuf/proto"
)

// relayAgents is a sender and a receiver agent joined by an in-process relay
// that forwards every tunnel frame (a copy, as a transport serializes).
// The relay hands tap every frame it forwards, serialized as it receives it.
func relayAgents(t *testing.T, ctx context.Context, tap func([]byte)) (sender, receiver *rpcclient.Agent) {
	t.Helper()
	src, dst := newMockSignalTunnel(ctx), newMockSignalTunnel(ctx)
	fwd := func(from, to *mockSignalTunnel) {
		for {
			select {
			case m := <-from.sendCh:
				if tap != nil {
					b, _ := proto.Marshal(m)
					tap(b)
				}
				select {
				case to.recvCh <- proto.Clone(m).(*pb.TunnelFrame):
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
	go fwd(src, dst)
	go fwd(dst, src)
	sender, receiver = rpcclient.NewAgent("sender", src), rpcclient.NewAgent("receiver", dst)
	t.Cleanup(func() { _ = sender.Close(); _ = receiver.Close() })
	return sender, receiver
}

// testBlob is random data with a run of repeated blocks (must survive every
// path intact).
func testBlob(t *testing.T, size int) string {
	t.Helper()
	b := make([]byte, size)
	_, _ = rand.Read(b[:size/2])
	p := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type transferResult struct {
	sendPath, recvPath string
	sendRace           []RaceEntry
	sendPair, recvPair string // the selected candidate pair, for failures
	sendErr, recvErr   error
	outDir             string
	relaySaw           []byte // every frame the relay forwarded
	sendFP, recvFP     string // the session fingerprints
}

// Which paths a test transfer offers besides WebRTC.
type xferMode int

const (
	webrtcOnly xferMode = iota
	forceRelay          // --force-relay: neither TCP nor WebRTC
	tcpLive             // the direct TCP channel connects (loopback)
	tcpDead             // TCP candidates that never answer
)

// tcpPair is each side's direct channel for mode (nil, nil without TCP).
func tcpPair(t *testing.T, mode xferMode) (sender, receiver *TCPDirect) {
	t.Helper()
	if mode != tcpLive && mode != tcpDead {
		return nil, nil
	}
	listen := func() *net.TCPListener {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return ln.(*net.TCPListener)
	}
	token := make([]byte, 32)
	_, _ = rand.Read(token)
	ls, lr := listen(), listen()
	toS, toR := ls.Addr().String(), lr.Addr().String()
	if mode == tcpDead {
		dead := listen()
		toS, toR = dead.Addr().String(), dead.Addr().String()
		_ = dead.Close()
	}
	return &TCPDirect{Listener: ls, Candidates: []string{toR}, Token: token, SessionID: "s1"},
		&TCPDirect{Listener: lr, Candidates: []string{toS}, Token: token, SessionID: "s1"}
}

// transfer runs `p2p send`/`recv`'s protocol-2 flow in process: offer/answer,
// RelayMux + SignalConn on the relay stream, OpenDataPath on both sides, then
// send (a file, or the directory at src) over the chosen path.
func transfer(t *testing.T, src string, mode xferMode, duringSend func(conn *DataPath, sent int64)) transferResult {
	t.Helper()
	tcpS, tcpR := tcpPair(t, mode)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var relayMu sync.Mutex
	var relaySaw bytes.Buffer
	sender, receiver := relayAgents(t, ctx, func(b []byte) {
		relayMu.Lock()
		relaySaw.Write(b)
		relayMu.Unlock()
	})
	info, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	res := transferResult{outDir: t.TempDir()}
	recvDone := make(chan struct{})
	receiver.Handle(func(stream rpcclient.ServerStream) error {
		defer close(recvDone)
		offer, err := RecvSignalServer(stream)
		if err != nil {
			res.recvErr = err
			return err
		}
		e, err := NewE2E(offer.Session, false, nil)
		if err != nil {
			res.recvErr = err
			return err
		}
		answer := &SignalMsg{Session: offer.Session, Proto: SignalProto}
		if err := e.Answer(offer, answer); err != nil {
			res.recvErr = err
			return err
		}
		if err := SendAnswer(stream, answer); err != nil {
			res.recvErr = err
			return err
		}
		if err := e.AwaitConfirm(stream); err != nil {
			res.recvErr = err
			return err
		}
		res.recvFP = e.Fingerprint()
		if tcpR != nil {
			tcpR.Token = e.DirectToken()
		}
		mux := NewServerRelayMux(stream)
		sc := e.SignalConn(mux.SignalPath())
		defer sc.Close() //nolint:errcheck
		dp, err := OpenDataPath(ctx, sc, mux, loopbackICE, tcpR, false, false)
		if err != nil {
			res.recvErr = err
			return err
		}
		defer dp.Conn.Close() //nolint:errcheck
		res.recvPath = dp.Path
		res.recvPair = pairDesc(dp)
		if info.IsDir() {
			res.recvErr = ReceiveDir(dp.Conn, res.outDir)
		} else {
			_, res.recvErr = ReceiveFile(dp.Conn, res.outDir, nil)
		}
		return res.recvErr
	})

	stream, err := sender.NewStream(ctx, "receiver")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewE2E("s1", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := SendOffer(stream, &SignalMsg{Session: "s1", Proto: SignalProto, Key: e.PublicKey(), Meta: &Meta{Op: "send-file"}}); err != nil {
		t.Fatal(err)
	}
	answer, err := RecvSignal(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.FinishOffer(stream, answer); err != nil {
		t.Fatal(err)
	}
	res.sendFP = e.Fingerprint()
	if tcpS != nil {
		tcpS.Token = e.DirectToken()
	}
	mux := NewClientRelayMux(stream)
	sc := e.SignalConn(mux.SignalPath())
	dp, err := OpenDataPath(ctx, sc, mux, loopbackICE, tcpS, true, mode == forceRelay)
	if err != nil {
		t.Fatalf("sender OpenDataPath: %v", err)
	}
	res.sendPath = dp.Path
	res.sendPair = pairDesc(dp)
	res.sendRace = dp.Race
	var progress ProgressFunc
	if duringSend != nil {
		progress = func(sent, _ int64) { duringSend(dp, sent) }
	}
	if info.IsDir() {
		res.sendErr = SendDir(dp.Conn, src, progress)
	} else {
		res.sendErr = SendFile(dp.Conn, src, progress)
	}
	_ = dp.Conn.Close()
	_ = sc.Close()
	select {
	case <-recvDone:
	case <-ctx.Done():
		t.Fatal("receiver did not finish")
	}
	relayMu.Lock()
	res.relaySaw = bytes.Clone(relaySaw.Bytes())
	relayMu.Unlock()
	return res
}

func assertSameFile(t *testing.T, a, b string) {
	t.Helper()
	x, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := os.ReadFile(b)
	if err != nil {
		t.Fatalf("received file: %v", err)
	}
	if !bytes.Equal(x, y) {
		t.Fatalf("%s differs from %s", b, a)
	}
}

// The file goes over the WebRTC data channel (host candidates on one
// machine), intact, with the sender and receiver agreeing on the path.
func TestFileOverDataChannel(t *testing.T) {
	src := testBlob(t, 24<<20)
	r := transfer(t, src, webrtcOnly, nil)
	if r.sendErr != nil || r.recvErr != nil {
		t.Fatalf("send: %v, recv: %v", r.sendErr, r.recvErr)
	}
	if r.sendPath != PathHost || r.recvPath != PathHost {
		t.Fatalf("paths %q/%q, want %q (pairs: send %s; recv %s)", r.sendPath, r.recvPath, PathHost, r.sendPair, r.recvPair)
	}
	assertRace(t, r.sendRace, RaceWebRTC+"="+RaceWon, PathRelay+"="+RaceLate)
	assertSameFile(t, src, filepath.Join(r.outDir, "blob.bin"))
}

// assertRace checks a sender's race, path=outcome per entry in order,
// each with a time.
func assertRace(t *testing.T, got []RaceEntry, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("race %+v, want %v", got, want)
	}
	for i, e := range got {
		if e.Path+"="+e.Outcome != want[i] || e.After <= 0 {
			t.Fatalf("race %+v, want %v with times", got, want)
		}
	}
}

func TestDirOverDataChannel(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tree")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a.txt", "sub/b.bin"} {
		if err := os.WriteFile(filepath.Join(dir, p), bytes.Repeat([]byte(p), 50000), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := transfer(t, dir, webrtcOnly, nil)
	if r.sendErr != nil || r.recvErr != nil || r.sendPath != PathHost {
		t.Fatalf("send: %v, recv: %v, path %q", r.sendErr, r.recvErr, r.sendPath)
	}
	assertSameFile(t, filepath.Join(dir, "sub/b.bin"), filepath.Join(r.outDir, "tree/sub/b.bin"))
}

// loopbackICE gathers host candidates on loopback only: the sender and the
// receiver share the machine, and ICE's work then does not grow with the
// host's interfaces (18 candidates a side on a Mac with Docker and IPv6
// privacy addresses: 324 pairs, 5-9 s of checks at load 20-50 under -race,
// against RTCWait's 10 s; the Linux runner's container has 2).
var loopbackICE = ICEConfig{ipFilter: func(ip net.IP) bool { return ip.IsLoopback() }}

// ICE between two sides on one machine connects in a small part of
// RTCWait, however many interfaces the machine has: a test that asserts the
// data channel path never races RTCWait.
func TestICEOnLoopbackConnectsWellWithinRTCWait(t *testing.T) {
	src := testBlob(t, 64<<10)
	start := time.Now()
	r := transfer(t, src, webrtcOnly, nil)
	if r.sendPath != PathHost {
		t.Fatalf("path %q, want %q (pairs: send %s; recv %s)", r.sendPath, PathHost, r.sendPair, r.recvPair)
	}
	if d := time.Since(start); d > RTCWait/2 {
		t.Fatalf("a 64 KiB transfer on loopback took %s; RTCWait is %s", d, RTCWait)
	}
}

// noICEPath: ICE gathers no candidate, so no data channel can open and the
// sender's RTCWait (short, to keep the test fast) is what decides. A short
// RTCWait alone is a race: ICE on loopback can be done before it starts.
func noICEPath(t *testing.T) {
	oldWait, oldTypes := RTCWait, rtcNetworkTypes
	RTCWait, rtcNetworkTypes = 50*time.Millisecond, []webrtc.NetworkType{webrtc.NetworkTypeTCP4}
	t.Cleanup(func() { RTCWait, rtcNetworkTypes = oldWait, oldTypes })
}

// No ICE path in time: the transfer goes over the relay stream, as before
// WebRTC, so it never fails where the relay works.
func TestFileFallsBackToRelayWhenICEFindsNoPath(t *testing.T) {
	noICEPath(t)
	src := testBlob(t, 3<<20)
	r := transfer(t, src, webrtcOnly, nil)
	if r.sendErr != nil || r.recvErr != nil {
		t.Fatalf("send: %v, recv: %v", r.sendErr, r.recvErr)
	}
	if r.sendPath != PathRelay || r.recvPath != PathRelay {
		t.Fatalf("paths %q/%q, want relay", r.sendPath, r.recvPath)
	}
	if len(r.sendRace) != 2 || r.sendRace[1].Outcome != RaceWon || r.sendRace[0].Outcome == RaceWon {
		t.Fatalf("race %+v, want the relay won", r.sendRace)
	}
	assertSameFile(t, src, filepath.Join(r.outDir, "blob.bin"))
}

// With the direct TCP channel up (a LAN), it wins the race: both sides use
// the same authenticated connection, and the data channel is closed.
func TestFileOverDirectTCPWhenItIsReadyFirst(t *testing.T) {
	src := testBlob(t, 24<<20)
	r := transfer(t, src, tcpLive, nil)
	if r.sendErr != nil || r.recvErr != nil {
		t.Fatalf("send: %v, recv: %v", r.sendErr, r.recvErr)
	}
	if r.sendPath != PathTCP || r.recvPath != PathTCP {
		t.Fatalf("paths %q/%q, want %q", r.sendPath, r.recvPath, PathTCP)
	}
	if len(r.sendRace) != 3 || r.sendRace[0].Path != PathTCP || r.sendRace[0].Outcome != RaceWon {
		t.Fatalf("race %+v, want TCP won", r.sendRace)
	}
	assertSameFile(t, src, filepath.Join(r.outDir, "blob.bin"))
}

// TCP candidates that never answer (across a NAT) do not hold the transfer
// back: the data channel wins.
func TestFileOverDataChannelWhenTCPNeverConnects(t *testing.T) {
	src := testBlob(t, 4<<20)
	r := transfer(t, src, tcpDead, nil)
	if r.sendErr != nil || r.recvErr != nil || r.sendPath != PathHost || r.recvPath != PathHost {
		t.Fatalf("send: %v, recv: %v, paths %q/%q (pairs: send %s; recv %s)", r.sendErr, r.recvErr, r.sendPath, r.recvPath, r.sendPair, r.recvPair)
	}
	assertSameFile(t, src, filepath.Join(r.outDir, "blob.bin"))
}

// The receiver follows the sender's TCP choice only on that exact
// connection: an announced ConnID it does not hold fails, never another conn.
func TestReceiverUsesOnlyTheAnnouncedTCPConn(t *testing.T) {
	old := RTCWait
	RTCWait = 200 * time.Millisecond
	defer func() { RTCWait = old }()
	_, d := tcpPair(t, tcpDead)
	s := &rtcSession{}
	s.startTCP(context.Background(), d)
	if c := s.waitTCP(context.Background(), "not-a-conn-id"); c != nil {
		t.Fatalf("got %v for an unknown ConnID", c)
	}
}

func TestFileForceRelay(t *testing.T) {
	src := testBlob(t, 1<<20)
	r := transfer(t, src, forceRelay, nil)
	if r.sendErr != nil || r.recvErr != nil || r.sendPath != PathRelay || r.recvPath != PathRelay {
		t.Fatalf("send: %v, recv: %v, paths %q/%q", r.sendErr, r.recvErr, r.sendPath, r.recvPath)
	}
	if r.sendRace != nil {
		t.Fatalf("race %+v with force relay", r.sendRace)
	}
	assertSameFile(t, src, filepath.Join(r.outDir, "blob.bin"))
}

// A data channel that dies mid-transfer fails both sides (no resume) and
// leaves no partial file.
func TestDataChannelDeathFailsTransfer(t *testing.T) {
	src := testBlob(t, 16<<20)
	var once sync.Once
	r := transfer(t, src, webrtcOnly, func(dp *DataPath, sent int64) {
		if sent > 2<<20 {
			once.Do(func() { _ = dp.Conn.Close() })
		}
	})
	if r.sendErr == nil || r.recvErr == nil {
		t.Fatalf("send: %v, recv: %v; both must fail", r.sendErr, r.recvErr)
	}
	if _, err := os.Stat(filepath.Join(r.outDir, "blob.bin")); !os.IsNotExist(err) {
		t.Fatalf("partial file left behind: %v", err)
	}
}

// chunkWriter sends at most chunk bytes per message and never lets more than
// high + chunk bytes queue, however much is written.
func TestChunkWriterBackPressure(t *testing.T) {
	const chunk, high = 1000, 10000
	var queued atomic.Int64
	var peak int64
	low := make(chan struct{}, 1)
	done := make(chan struct{})
	defer close(done)
	go func() { // the network drains the queue and signals low water
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
			}
			if q := queued.Load(); q > 0 {
				queued.Add(-min(q, 3000))
				select {
				case low <- struct{}{}:
				default:
				}
			}
		}
	}()
	var sent bytes.Buffer
	w := &chunkWriter{
		send: func(b []byte) error {
			if len(b) > chunk {
				t.Errorf("message of %d bytes, chunk is %d", len(b), chunk)
			}
			sent.Write(b)
			if q := queued.Add(int64(len(b))); q > peak {
				peak = q
			}
			return nil
		},
		buffered: func() uint64 { return uint64(queued.Load()) },
		low:      low,
		done:     make(chan struct{}),
		chunk:    chunk,
		high:     high,
	}
	data := make([]byte, 500_000)
	_, _ = rand.Read(data)
	if n, err := w.Write(data); err != nil || n != len(data) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if !bytes.Equal(sent.Bytes(), data) {
		t.Fatal("chunks do not reassemble the input")
	}
	if peak > high+chunk {
		t.Fatalf("queue peaked at %d bytes, bound is %d", peak, high+chunk)
	}
	close(w.done)
	queued.Store(high + 1)
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("a write on a closed conn must fail, not wait")
	}
}

func TestPathName(t *testing.T) {
	h, s, p, r := webrtc.ICECandidateTypeHost, webrtc.ICECandidateTypeSrflx, webrtc.ICECandidateTypePrflx, webrtc.ICECandidateTypeRelay
	for _, c := range []struct {
		l, r webrtc.ICECandidateType
		want string
	}{{h, h, PathHost}, {s, s, PathSrflx}, {h, p, PathSrflx}, {r, p, PathTURN}, {p, r, PathTURN}} {
		if got := pathName(c.l, c.r); got != c.want {
			t.Errorf("pathName(%v, %v) = %q, want %q", c.l, c.r, got, c.want)
		}
	}
}

// A check from the peer's unsignaled link-local socket, or from an address
// of this machine, makes ICE learn it as peer-reflexive; that path has no
// NAT on it, so it is a host path.
func TestRemoteTypeLinkLocalPrflxIsHost(t *testing.T) {
	p, h := webrtc.ICECandidateTypePrflx, webrtc.ICECandidateTypeHost
	for _, c := range []struct {
		cand webrtc.ICECandidate
		want webrtc.ICECandidateType
	}{
		{webrtc.ICECandidate{Typ: p, Address: "fe80::18e2:3e56:5e9c:70ef"}, h},
		{webrtc.ICECandidate{Typ: p, Address: "fe80::1%en0"}, h},
		{webrtc.ICECandidate{Typ: p, Address: "169.254.3.4"}, h},
		{webrtc.ICECandidate{Typ: p, Address: "127.0.0.1"}, h},    // this machine's
		{webrtc.ICECandidate{Typ: p, Address: "198.51.100.9"}, p}, // a NAT's mapping
		{webrtc.ICECandidate{Typ: p, Address: "2001:db8::1"}, p},
		{webrtc.ICECandidate{Typ: webrtc.ICECandidateTypeSrflx, Address: "fe80::1"}, webrtc.ICECandidateTypeSrflx},
		{webrtc.ICECandidate{Typ: webrtc.ICECandidateTypeRelay, Address: "fe80::1"}, webrtc.ICECandidateTypeRelay},
	} {
		if got := remoteType(c.cand); got != c.want {
			t.Errorf("remoteType(%v %s) = %v, want %v", c.cand.Typ, c.cand.Address, got, c.want)
		}
	}
}

func pairDesc(dp *DataPath) string {
	return fmt.Sprintf("%s %v -> %v", dp.Pair, dp.Conn.LocalAddr(), dp.Conn.RemoteAddr())
}
