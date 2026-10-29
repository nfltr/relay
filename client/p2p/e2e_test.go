// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nfltr/relay/client/rpcclient"
)

// fakeClient / fakeServer are the two ends of one relay stream.
type fakeClient struct {
	rpcclient.ClientStream
	out chan<- []byte
	in  <-chan []byte
}

func (f fakeClient) Send(b []byte) error { f.out <- bytes.Clone(b); return nil }
func (f fakeClient) Recv() (*rpcclient.Response, error) {
	return &rpcclient.Response{Data: <-f.in}, nil
}

type fakeServer struct {
	rpcclient.ServerStream
	out chan<- []byte
	in  <-chan []byte
}

func (f fakeServer) Send(b []byte) error   { f.out <- bytes.Clone(b); return nil }
func (f fakeServer) Recv() ([]byte, error) { return <-f.in, nil }

func streamPair() (fakeClient, fakeServer) {
	c2s, s2c := make(chan []byte, 16), make(chan []byte, 16)
	return fakeClient{out: c2s, in: s2c}, fakeServer{out: s2c, in: c2s}
}

func pairingKey() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

// e2eHandshake runs offer → answer → confirm between an initiator and a
// responder with these pairing keys.
func e2eHandshake(t *testing.T, pi, pr []byte) (ini, res *E2E, iniErr, resErr error) {
	t.Helper()
	ini, _ = NewE2E("s1", true, pi)
	res, _ = NewE2E("s1", false, pr)
	cs, ss := streamPair()
	answer := &SignalMsg{Session: "s1", Proto: SignalProto}
	if err := res.Answer(&SignalMsg{Key: ini.PublicKey()}, answer); err != nil {
		t.Fatal(err)
	}
	iniErr = ini.FinishOffer(cs, answer)
	resErr = res.AwaitConfirm(ss)
	return ini, res, iniErr, resErr
}

func TestE2EKeyExchangeAgrees(t *testing.T) {
	ini, res, ie, re := e2eHandshake(t, nil, nil)
	if ie != nil || re != nil {
		t.Fatalf("initiator: %v, responder: %v", ie, re)
	}
	if ini.Fingerprint() != res.Fingerprint() {
		t.Fatalf("fingerprints differ: %s / %s", ini.Fingerprint(), res.Fingerprint())
	}
	if !regexp.MustCompile(`^[0-9A-F]{4}(-[0-9A-F]{4}){4}$`).MatchString(ini.Fingerprint()) {
		t.Fatalf("fingerprint %q", ini.Fingerprint())
	}
	if !bytes.Equal(ini.DirectToken(), res.DirectToken()) || len(ini.DirectToken()) != 32 {
		t.Fatal("direct-channel secrets differ")
	}
	other, _, _, _ := e2eHandshake(t, nil, nil)
	if other.Fingerprint() == ini.Fingerprint() {
		t.Fatal("two sessions share a fingerprint: keys are not ephemeral")
	}
}

func TestE2EPairingKey(t *testing.T) {
	k := pairingKey()
	if _, _, ie, re := e2eHandshake(t, k, k); ie != nil || re != nil {
		t.Fatalf("same pairing key: %v / %v", ie, re)
	}
	for name, keys := range map[string][2][]byte{
		"different keys":     {pairingKey(), pairingKey()},
		"only the initiator": {k, nil},
		"only the responder": {nil, k},
	} {
		_, _, ie, re := e2eHandshake(t, keys[0], keys[1])
		if !errors.Is(ie, ErrE2EMismatch) {
			t.Fatalf("%s: initiator %v, want ErrE2EMismatch", name, ie)
		}
		if re == nil || !strings.Contains(re.Error(), "pairing keys") {
			t.Fatalf("%s: responder %v, want the initiator's reason", name, re)
		}
	}
}

// A relay that replaces both public keys runs two key exchanges. Without a
// pairing key both legs confirm, but the fingerprints differ; with one the
// relay cannot confirm either leg.
func TestE2ERelayInTheMiddle(t *testing.T) {
	for _, k := range [][]byte{nil, pairingKey()} {
		a, _ := NewE2E("s1", true, k)
		b, _ := NewE2E("s1", false, k)
		mb, _ := NewE2E("s1", true, nil)  // the relay toward b, as initiator
		ma, _ := NewE2E("s1", false, nil) // the relay toward a, as responder
		ansB := &SignalMsg{}
		if err := b.Answer(&SignalMsg{Key: mb.PublicKey()}, ansB); err != nil {
			t.Fatal(err)
		}
		ansA := &SignalMsg{}
		if err := ma.Answer(&SignalMsg{Key: a.PublicKey()}, ansA); err != nil {
			t.Fatal(err)
		}
		cs, _ := streamPair()
		errA := a.FinishOffer(cs, ansA)
		if k == nil {
			if errA != nil {
				t.Fatalf("unpaired leg: %v", errA)
			}
			_ = mb.Complete(ansB.Key)
			if a.Fingerprint() == b.Fingerprint() {
				t.Fatal("a relay in the middle left the fingerprints equal")
			}
			continue
		}
		if !errors.Is(errA, ErrE2EMismatch) {
			t.Fatalf("paired: relay in the middle got %v, want ErrE2EMismatch", errA)
		}
	}
}

func TestE2ERejectsMissingOrBadKey(t *testing.T) {
	e, _ := NewE2E("s1", false, nil)
	for _, k := range []string{"", "zz", strings.Repeat("00", 32)} { // empty, not hex, low order
		if err := e.Answer(&SignalMsg{Key: k}, &SignalMsg{}); err == nil {
			t.Fatalf("key %q accepted", k)
		}
	}
}

// recordConn is a net.Conn whose writes go to w and reads come from r.
type recordConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

// Read reads r (net.Conn). allow:wrapper
func (c recordConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Write writes w (net.Conn). allow:wrapper
func (c recordConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func TestSecureConnRecords(t *testing.T) {
	ini, res, _, _ := e2eHandshake(t, nil, nil)
	plain := bytes.Repeat([]byte("nfltr-canary-0123456789"), 20000) // several records
	var wire bytes.Buffer
	w := ini.Secure(recordConn{w: &wire})
	if n, err := w.Write(plain); err != nil || n != len(plain) {
		t.Fatalf("write %d, %v", n, err)
	}
	ct := bytes.Clone(wire.Bytes())
	if bytes.Contains(ct, []byte("nfltr-canary")) {
		t.Fatal("plaintext on the wire")
	}
	read := func(b []byte) ([]byte, error) {
		return io.ReadAll(res.Secure(recordConn{r: bytes.NewReader(b)}))
	}
	if got, err := read(ct); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %d bytes, %v", len(got), err)
	}

	tampered := bytes.Clone(ct)
	tampered[100] ^= 1
	if _, err := read(tampered); !errors.Is(err, errE2ETampered) {
		t.Fatalf("altered byte: %v", err)
	}
	rec := 4 + int(uint32(ct[0])<<24|uint32(ct[1])<<16|uint32(ct[2])<<8|uint32(ct[3]))
	if _, err := read(append(bytes.Clone(ct[:rec]), ct...)); !errors.Is(err, errE2ETampered) {
		t.Fatalf("replayed record: %v", err)
	}
	if _, err := read(append(bytes.Clone(ct[rec:2*rec]), ct[:rec]...)); !errors.Is(err, errE2ETampered) {
		t.Fatalf("reordered records: %v", err)
	}
	if _, err := read(ct[:rec+10]); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("cut mid-record: %v", err)
	}
	// The responder's own direction key cannot read the initiator's records.
	if _, err := io.ReadAll(ini.Secure(recordConn{r: bytes.NewReader(ct)})); !errors.Is(err, errE2ETampered) {
		t.Fatalf("reflected records: %v", err)
	}
}

// pipePath is a FramePath on a channel.
type pipePath struct{ in, out chan *Frame }

func (p pipePath) WriteFrame(f *Frame) error { g := *f; p.out <- &g; return nil }
func (p pipePath) ReadFrame() (*Frame, error) {
	f, ok := <-p.in
	if !ok {
		return nil, io.EOF
	}
	return f, nil
}
func (p pipePath) Close() error { return nil }

func TestSealedSignalFrames(t *testing.T) {
	ini, res, _, _ := e2eHandshake(t, nil, nil)
	wire := make(chan *Frame, 4)
	w := ini.sealPath(pipePath{out: wire})
	r := res.sealPath(pipePath{in: wire})
	if err := w.WriteFrame(&Frame{Type: FrameChat, Text: "secret chat", Seq: 1}); err != nil {
		t.Fatal(err)
	}
	f := <-wire
	if f.Type != frameSealed || strings.Contains(f.Text, "secret") {
		t.Fatalf("frame on the wire: %+v", f)
	}
	wire <- f
	if g, err := r.ReadFrame(); err != nil || g.Text != "secret chat" || g.Seq != 1 {
		t.Fatalf("read %+v, %v", g, err)
	}
	for name, bad := range map[string]*Frame{
		"plain frame":    {Type: FrameChat, Text: "hi", Seq: 2},
		"altered":        {Type: frameSealed, Seq: 1, Text: f.Text[:len(f.Text)-4] + "AAAA"},
		"moved sequence": {Type: frameSealed, Seq: 7, Text: f.Text},
	} {
		wire <- bad
		if _, err := r.ReadFrame(); !errors.Is(err, errE2ETampered) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := w.WriteFrame(&Frame{Type: FrameChat}); err == nil {
		t.Fatal("an unsequenced frame was sealed")
	}
}

func TestOpenDataPathRefusesPlainSignalConn(t *testing.T) {
	in := make(chan *Frame)
	defer close(in) // ends the path's reader goroutine
	_, err := OpenDataPath(t.Context(), NewSignalConn(pipePath{in: in}), nil, ICEConfig{}, nil, true, true)
	if err == nil || !strings.Contains(err.Error(), "end-to-end") {
		t.Fatalf("got %v", err)
	}
}

// Every path of a real transfer (offer/answer through an in-process relay,
// then the data on the relay, the direct TCP channel or WebRTC): the relay
// never sees the file's bytes, its name, its SHA-256 or the WebRTC SDP.
func TestRelayNeverSeesTransferPlaintext(t *testing.T) {
	canary := []byte("NFLTR-PLAINTEXT-CANARY-7f3a9c")
	cases := []struct {
		name  string
		mode  xferMode
		noICE bool
		path  string
		bulky bool // the data crossed the relay (as ciphertext)
	}{
		{"relay (--force-relay)", forceRelay, false, PathRelay, true},
		{"relay fallback", webrtcOnly, true, PathRelay, true},
		{"tcp-direct", tcpLive, false, PathTCP, false},
		{"webrtc", webrtcOnly, false, PathHost, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.noICE {
				noICEPath(t)
			}
			src := filepath.Join(t.TempDir(), "quarterly-secret-report.txt")
			body := bytes.Repeat(canary, (2<<20)/len(canary))
			if err := os.WriteFile(src, body, 0o600); err != nil {
				t.Fatal(err)
			}
			r := transfer(t, src, c.mode, nil)
			if r.sendErr != nil || r.recvErr != nil || r.sendPath != c.path {
				t.Fatalf("send: %v, recv: %v, path %q", r.sendErr, r.recvErr, r.sendPath)
			}
			assertSameFile(t, src, filepath.Join(r.outDir, "quarterly-secret-report.txt"))
			if r.sendFP == "" || r.sendFP != r.recvFP {
				t.Fatalf("fingerprints %q / %q", r.sendFP, r.recvFP)
			}
			h := sha256.Sum256(body)
			sum := hex.EncodeToString(h[:])
			for _, leak := range [][]byte{canary, []byte("quarterly-secret-report"), []byte(sum), []byte("a=fingerprint"), []byte("candidate:")} {
				if bytes.Contains(r.relaySaw, leak) {
					t.Fatalf("the relay saw %q", leak)
				}
			}
			if c.bulky && len(r.relaySaw) < len(body) {
				t.Fatalf("the relay forwarded %d bytes, less than the %d-byte file: the capture missed the data", len(r.relaySaw), len(body))
			}
			if !bytes.Contains(r.relaySaw, []byte(`"key":"`)) { // the public keys: what it may see
				t.Fatal("the capture holds no offer")
			}
		})
	}
}
