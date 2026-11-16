// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

// The bindings spec/proverif/p2p_e2e.pv relies on, against the real code:
// each BIND:<id> the model lists has one row here that changes just that
// field of an honest session, as a relay can, and requires the code to
// refuse (or, for the fingerprint, the two ends to print different ones).
// The key exchange runs the real offer, answer and confirmation messages
// through a relay of this file; the signaling frames run on real
// SignalConns; the DTLS row runs two real pion peer connections on
// loopback. `make spec-bindings`.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/internal/modelbind"
	"github.com/pion/webrtc/v4"
)

const p2pBindModel = "../../spec/proverif/p2p_e2e.pv"

// bindRoot is a root key holder's Pair, as the model's pairKey/pairKid
// (nfltr a2akeys PairKeys): the root key with a root peer, else the machine
// key of the peer's key id. named is the responder's machine the initiator
// named ("" a bare name: the root key); a responder names none (any).
// errNotNamed is bindRoot's refusal of a key id it did not name.
var errNotNamed = errors.New("not the machine named")

type bindRoot struct {
	r     []byte
	named *string
}

func (bindRoot) KeyID() string { return "" }

func (p bindRoot) Key(peer string) ([]byte, string, error) {
	if p.named != nil && peer != *p.named {
		return nil, "", fmt.Errorf("key id %q, named %q: %w", peer, *p.named, errNotNamed)
	}
	if peer == "" {
		return p.r, "", nil
	}
	return bindMK(p.r, peer), peer, nil
}

// bindMachine is machine id's Pair: its own key, with a root peer or one of
// its own machine.
type bindMachine struct {
	id string
	k  []byte
}

func (p bindMachine) KeyID() string { return p.id }

func (p bindMachine) Key(peer string) ([]byte, string, error) {
	if peer != "" && peer != p.id {
		return nil, "", fmt.Errorf("machine %s: peer key id %q", p.id, peer)
	}
	return p.k, p.id, nil
}

// bindMK stands in for a2akeys.Derive(root, id).
func bindMK(r []byte, id string) []byte {
	m := hmac.New(sha256.New, r)
	m.Write([]byte(id))
	return m.Sum(nil)
}

var bindR = bytes.Repeat([]byte{0x52}, 32)

func named(id string) *string { return &id }

func machinePair(id string) bindMachine { return bindMachine{id: id, k: bindMK(bindR, id)} }

// bindSession is one session's two ends: the initiator's sid, the name it
// calls and its Pair; the responder's name and Pair (nil: unpaired).
type bindSession struct {
	sid                string
	callee, respName   string
	iniPair, respPair  Pair
	offer, answer, cfm func(*SignalMsg) // the relay's changes (nil: none)
}

type bindResult struct {
	ini, res       *E2E
	iniErr, resErr error
}

// relayMsg is the relay forwarding a signaling message: decoded, changed
// by change, encoded again.
func relayMsg(t *testing.T, b []byte, change func(*SignalMsg)) []byte {
	t.Helper()
	if change == nil {
		return b
	}
	var m SignalMsg
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	change(&m)
	out, err := json.Marshal(&m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// run runs offer, answer and confirmation through the relay as nfltr's p2p
// commands did: the responder's E2E is for the offer's session.
func (s bindSession) run(t *testing.T) bindResult {
	t.Helper()
	cOut, cIn, sOut, sIn := make(chan []byte, 1), make(chan []byte, 1), make(chan []byte, 1), make(chan []byte, 1)
	cs, ss := fakeClient{out: cOut, in: cIn}, fakeServer{out: sOut, in: sIn}
	var r bindResult
	r.ini, _ = NewE2E(s.sid, true, s.callee, s.iniPair)
	if err := SendOffer(cs, &SignalMsg{Session: s.sid, Proto: SignalProto, Key: r.ini.PublicKey(), KeyID: r.ini.KeyID()}); err != nil {
		t.Fatal(err)
	}
	sIn <- relayMsg(t, <-cOut, s.offer)
	offer, err := RecvSignalServer(ss)
	if err != nil {
		t.Fatal(err)
	}
	r.res, _ = NewE2E(offer.Session, false, s.respName, s.respPair)
	answer := &SignalMsg{Session: offer.Session, Proto: SignalProto}
	if r.resErr = r.res.Answer(offer, answer); r.resErr != nil {
		return r
	}
	if err := SendAnswer(ss, answer); err != nil {
		t.Fatal(err)
	}
	cIn <- relayMsg(t, <-sOut, s.answer)
	if answer, err = RecvSignal(cs); err != nil {
		t.Fatal(err)
	}
	r.iniErr = r.ini.FinishOffer(cs, answer) // a confirmation, or a hangup
	sIn <- relayMsg(t, <-cOut, s.cfm)
	r.resErr = r.res.AwaitConfirm(ss)
	return r
}

// honestCall is a root initiator calling home1 on machine m1.
func honestCall() bindSession {
	return bindSession{sid: "s1", callee: "home1", respName: "home1",
		iniPair: bindRoot{r: bindR, named: named("m1")}, respPair: machinePair("m1")}
}

func agreed(t *testing.T, s bindSession) {
	t.Helper()
	if r := s.run(t); r.iniErr != nil || r.resErr != nil {
		t.Fatalf("honest session refused: initiator %v, responder %v", r.iniErr, r.resErr)
	}
}

func iniRefuses(t *testing.T, what string, s bindSession) {
	t.Helper()
	if r := s.run(t); r.iniErr == nil {
		t.Fatalf("%s: the initiator accepted", what)
	}
}

func respRefuses(t *testing.T, what string, s bindSession) {
	t.Helper()
	r := s.run(t)
	if r.iniErr != nil {
		t.Fatalf("%s: the initiator refused first: %v", what, r.iniErr)
	}
	if r.resErr == nil {
		t.Fatalf("%s: the responder accepted", what)
	}
}

// flip changes a hex string's first character.
func flip(s string) string {
	if s == "" {
		return "00"
	}
	c := byte('0')
	if s[0] == '0' {
		c = '1'
	}
	return string(c) + s[1:]
}

var p2pBindings = map[string]func(t *testing.T){
	// hsalt(K, name, kid): name. A call for home3 routed to office3, on the
	// same machine (one key; finding 5, mutant name-unbound)
	"p2p.salt.name": func(t *testing.T) {
		s := bindSession{sid: "s1", callee: "home3", respName: "home3",
			iniPair: bindRoot{r: bindR, named: named("m3")}, respPair: machinePair("m3")}
		agreed(t, s)
		s.respName = "office3"
		iniRefuses(t, "home3's call answered by office3", s)
	},
	// hsalt(K, name, kid): kid. The offer's key id is the relay's word to a
	// root responder: machine m2 calling hub2, the relay naming m3 or the
	// root key instead (bound twice: the key the responder derives too)
	"p2p.salt.kid": func(t *testing.T) {
		s := bindSession{sid: "s1", callee: "hub2", respName: "hub2",
			iniPair: machinePair("m2"), respPair: bindRoot{r: bindR}}
		agreed(t, s)
		for _, kid := range []string{"m3", ""} {
			s.offer = func(m *SignalMsg) { m.KeyID = kid }
			iniRefuses(t, "offer key id "+kid, s)
		}
	},
	// rkid = named: a root initiator takes the answer's key id only for the
	// machine it named (lane ROOTNAMEPIN, mutant relay-kid; the check is
	// the Pair's, nfltr a2akeys PairKeys.Key): the relay, holding leaked
	// machine mL's key, answers home1's call as mL, or as m2's home1
	"p2p.kid.named": func(t *testing.T) {
		agreed(t, honestCall())
		for _, m := range []string{"mL", "m2"} {
			s := honestCall()
			s.respPair = machinePair(m)
			// Refused by the Pair, not only by the confirmation: a refusal
			// ignored leaves a salt the relay may compute.
			if r := s.run(t); !errors.Is(r.iniErr, errNotNamed) {
				t.Fatalf("home1 answered under %s's key: initiator %v, want the Pair's refusal", m, r.iniErr)
			}
		}
	},
	// th(sid, ipub, rpub): the relay hands the responder the offer under
	// another session id
	"p2p.transcript": func(t *testing.T) {
		s := honestCall()
		s.offer = func(m *SignalMsg) { m.Session = "s2" }
		iniRefuses(t, "offer moved to session s2", s)
	},
	// hmac(k_confirm, rResp): the initiator checks the answer's
	// confirmation (FinishOffer)
	"p2p.confirm.resp": func(t *testing.T) {
		for name, change := range map[string]func(*SignalMsg){
			"altered": func(m *SignalMsg) { m.Confirm = flip(m.Confirm) },
			"dropped": func(m *SignalMsg) { m.Confirm = "" },
		} {
			s := honestCall()
			s.answer = change
			iniRefuses(t, "answer confirmation "+name, s)
		}
	},
	// hmac(k_confirm, rInit): the responder checks the initiator's
	// confirmation (AwaitConfirm; mutant skip-await-confirm), role bound
	"p2p.confirm.init": func(t *testing.T) {
		for name, change := range map[string]func(*SignalMsg){
			"altered": func(m *SignalMsg) { m.Confirm = flip(m.Confirm) },
			"dropped": func(m *SignalMsg) { m.Type, m.Confirm = SignalHangup, "" },
			"retyped": func(m *SignalMsg) { m.Type = SignalAnswer },
		} {
			s := honestCall()
			s.cfm = change
			respRefuses(t, "initiator confirmation "+name, s)
		}
		// The responder's own tag reflected as the initiator's.
		var tag string
		s := honestCall()
		s.answer = func(m *SignalMsg) { tag = m.Confirm }
		s.cfm = func(m *SignalMsg) { m.Confirm = tag }
		respRefuses(t, "the responder's confirmation reflected", s)
	},
	// hkdfExpand(prk, lFp, t): unpaired, a relay in the middle completes
	// both legs, but the two ends print different fingerprints (query 6,
	// mutant fingerprint-not-compared: the users' comparison)
	"p2p.fingerprint": func(t *testing.T) {
		s := bindSession{sid: "s1", callee: "home4", respName: "home4"}
		r := s.run(t)
		if r.iniErr != nil || r.resErr != nil || r.ini.Fingerprint() != r.res.Fingerprint() {
			t.Fatalf("honest unpaired session: %v %v, fingerprints %s %s", r.iniErr, r.resErr, r.ini.Fingerprint(), r.res.Fingerprint())
		}
		a, _ := NewE2E("s1", true, "home4", nil)
		b, _ := NewE2E("s1", false, "home4", nil)
		ma, _ := NewE2E("s1", false, "home4", nil) // the relay toward a
		mb, _ := NewE2E("s1", true, "home4", nil)  // the relay toward b
		ansA, ansB := &SignalMsg{}, &SignalMsg{}
		if err := ma.Answer(&SignalMsg{Key: a.PublicKey()}, ansA); err != nil {
			t.Fatal(err)
		}
		if err := b.Answer(&SignalMsg{Key: mb.PublicKey()}, ansB); err != nil {
			t.Fatal(err)
		}
		cs, _ := streamPair()
		if err := a.FinishOffer(cs, ansA); err != nil {
			t.Fatal(err)
		}
		if a.Fingerprint() == b.Fingerprint() {
			t.Fatal("a relay in the middle left the two fingerprints equal")
		}
	},
	// senc(dfp, k_signal): the SDP travels in a sealed signaling frame;
	// the relay's own SDP, an altered or moved frame, and the responder's
	// own frame reflected are not delivered (mutant sdp-not-sealed)
	"p2p.sdp.sealed": func(t *testing.T) {
		r := honestCall().run(t)
		if r.iniErr != nil || r.resErr != nil {
			t.Fatal(r.iniErr, r.resErr)
		}
		sdp := rtcFrame(t, "v=0 the initiator's SDP")
		honest := sealedFrame(t, r.ini, sdp)
		own := sealedFrame(t, r.res, sdp)
		if got := deliver(t, r.res, honest); got == nil || got.Text != sdp.Text {
			t.Fatalf("honest sealed SDP: got %+v", got)
		}
		for name, f := range map[string]*Frame{
			"the relay's SDP": {Type: FrameRTC, Seq: 1, Text: rtcFrame(t, "v=0 the relay's SDP").Text},
			"altered":         {Type: frameSealed, Seq: 1, Text: honest.Text[:len(honest.Text)-4] + "AAAA"},
			"moved":           {Type: frameSealed, Seq: 2, Text: honest.Text},
			"reflected":       own,
		} {
			if got := deliver(t, r.res, f); got != nil {
				t.Fatalf("%s: delivered %+v", name, got)
			}
		}
	},
	// dfp(peerDtls) = fpPeer: an end takes the DTLS peer only under the
	// fingerprint its peer's SDP named (mutant accept-any-dtls): the
	// answer's fingerprint changed, the data channel never opens and the
	// sender falls back to the relay
	"p2p.dtls.fp": func(t *testing.T) {
		if p := dtlsPath(t, false); p == PathRelay {
			t.Fatalf("honest SDP: data path %s, want the data channel", p)
		}
		if p := dtlsPath(t, true); p != PathRelay {
			t.Fatalf("the answer's DTLS fingerprint changed: data path %s, want %s", p, PathRelay)
		}
	},
}

func rtcFrame(t *testing.T, sdp string) *Frame {
	t.Helper()
	b, err := json.Marshal(rtcSignal{SDP: &webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}})
	if err != nil {
		t.Fatal(err)
	}
	return &Frame{Type: FrameRTC, Text: string(b)}
}

// sealedFrame is the first frame e's SignalConn writes for f, as the relay
// sees it.
func sealedFrame(t *testing.T, e *E2E, f *Frame) *Frame {
	t.Helper()
	in, out := make(chan *Frame), make(chan *Frame, 1)
	sc := e.SignalConn(pipePath{in: in, out: out})
	if err := sc.WriteFrame(f); err != nil {
		t.Fatal(err)
	}
	g := <-out
	close(in)
	_ = sc.Close()
	return g
}

// deliver hands f to a fresh SignalConn of e and returns the frame it
// delivers, or nil when it refuses f (the path ends).
func deliver(t *testing.T, e *E2E, f *Frame) *Frame {
	t.Helper()
	in := make(chan *Frame, 1)
	sc := e.SignalConn(pipePath{in: in, out: make(chan *Frame, 1)})
	defer sc.Close() //nolint:errcheck
	in <- f
	close(in)
	g, err := sc.ReadFrame()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		return nil
	}
	return g
}

var dtlsFingerprint = regexp.MustCompile(`a=fingerprint:sha-256 [0-9A-F:]+`)

// dtlsPath runs the data-path negotiation of two real peer connections on
// loopback, the relay forwarding their signaling frames (below the seal:
// what it could do were the SDP unsealed) and, when changeFP, replacing
// the answer's DTLS fingerprint. It returns the sender's data path.
func dtlsPath(t *testing.T, changeFP bool) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ini2r, r2relay, relay2ini, r2ini := make(chan *Frame, 64), make(chan *Frame, 64), make(chan *Frame, 64), make(chan *Frame, 64)
	scI := NewSignalConn(pipePath{in: r2ini, out: ini2r})
	scR := NewSignalConn(pipePath{in: relay2ini, out: r2relay})
	forward := func(from <-chan *Frame, to chan<- *Frame, change bool) {
		for {
			select {
			case f := <-from:
				if change && f.Type == FrameRTC && strings.Contains(f.Text, `"answer"`) {
					var m rtcSignal
					if err := json.Unmarshal([]byte(f.Text), &m); err != nil {
						t.Error(err)
						return
					}
					fp := dtlsFingerprint.FindString(m.SDP.SDP)
					if fp == "" {
						t.Error("the answer names no DTLS fingerprint")
						return
					}
					m.SDP.SDP = strings.Replace(m.SDP.SDP, fp, regexp.MustCompile(`[0-9A-F]`).ReplaceAllString(fp, "0"), 1)
					b, _ := json.Marshal(m)
					g := *f
					g.Text = string(b)
					f = &g
				}
				to <- f
			case <-ctx.Done():
				return
			}
		}
	}
	go forward(ini2r, relay2ini, false)
	go forward(r2relay, r2ini, changeFP)
	mux := func() *RelayMux { return newRelayMux(func([]byte) error { return nil }, nil) }
	type res struct {
		dp  *DataPath
		err error
	}
	recv := make(chan res, 1)
	go func() {
		dp, err := openDataPath(ctx, scR, mux(), loopbackICE, nil, false, false)
		recv <- res{dp, err}
	}()
	dp, err := openDataPath(ctx, scI, mux(), loopbackICE, nil, true, false)
	if err != nil {
		t.Fatal(err)
	}
	rr := <-recv
	if rr.err != nil {
		t.Fatalf("receiver: %v", rr.err)
	}
	if rr.dp.Path != dp.Path {
		t.Fatalf("receiver on %s, sender on %s", rr.dp.Path, dp.Path)
	}
	_ = dp.Conn.Close()
	_ = rr.dp.Conn.Close()
	_ = scI.Close()
	_ = scR.Close()
	close(r2ini)
	close(relay2ini)
	cancel()
	return dp.Path
}

// TestP2PE2EModelBindings runs every row, and fails when the model's BIND
// ids and the rows differ.
func TestP2PE2EModelBindings(t *testing.T) {
	src, err := os.ReadFile(p2pBindModel)
	if err != nil {
		t.Fatal(err)
	}
	rows := slices.Sorted(maps.Keys(p2pBindings))
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:([a-z0-9.]+)`), rows); err != nil {
		t.Fatalf("%s: %v", p2pBindModel, err)
	}
	for _, id := range rows {
		t.Run(id, p2pBindings[id])
	}
}
