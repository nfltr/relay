// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// A2A E2EE 0-RTT first flight: Noise NK (NKpsk0 with a pairing key) to the
// static key a peer advertises as a connect label, the call's first request
// in the first message (0-RTT first flight for A2A E2EE).

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const (
	a2aE2EEInit0RTTMessageType = "a2a-e2ee-init-0rtt"
	a2aE2EERetryMessageType    = "a2a-e2ee-retry"

	// A2AE2EEStaticLabel is the connect label an E2EE agent advertises its
	// static key under; LearnA2AE2EEPeer reads it.
	A2AE2EEStaticLabel = "nfltr.a2a.e2ee.static"

	a2aE2EE0RTTVersion = 1
	// a2aE2EE0RTTWindow is the clock-skew tolerance between the two ends: a
	// first flight whose timestamp is further from the responder's clock is
	// refused (clock), and the call takes the interactive handshake. It must
	// exceed a2aE2EEHandshakeTimeout, the longest an initiator honours a retry.
	a2aE2EE0RTTWindow = 60 * time.Second
	// a2aE2EE0RTTSeenMax bounds the replay register.
	a2aE2EE0RTTSeenMax = 1 << 14

	a2aE2EE0RTTHeadLen = 1 + 8 // version, timestamp
	a2aE2EE0RTTMsg1Len = a2aE2EEPubLen + 32 + 16
	a2aE2EE0RTTMinLen  = a2aE2EE0RTTHeadLen + a2aE2EEPubLen + a2aE2EE0RTTMsg1Len + 12 + 16
	a2aE2EE0RTTContext = "nfltr-a2a-e2ee-0rtt-v1"
)

// a2aE2EERefusal is why a responder did not take a first flight.
type a2aE2EERefusal byte

const (
	refuseStale  a2aE2EERefusal = 1 + iota // not this process's static key (restarted)
	refuseClock                            // timestamp outside the window
	refuseBad                              // malformed, or failed decryption
	refuseBusy                             // replay register full
	refuseReplay                           // ephemeral key seen before: never retried
)

var a2aE2EESuite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

var a2aE2EEB64 = base64.RawURLEncoding

// a2aE2EEStatic is a process's static key and the replay register of the
// first flights sent to it.
type a2aE2EEStatic struct {
	key noise.DHKey

	mu        sync.Mutex
	seen      map[[a2aE2EEPubLen]byte]time.Time // ephemeral key -> kept until
	fullUntil time.Time
}

func newA2AE2EEStatic(rng io.Reader) (*a2aE2EEStatic, error) {
	key, err := a2aE2EESuite.GenerateKeypair(rng)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: generate A2A E2EE static key: %w", err)
	}
	return &a2aE2EEStatic{key: key, seen: map[[a2aE2EEPubLen]byte]time.Time{}}, nil
}

// processA2AE2EEStatic is the process's static key, made on first use and
// held in memory only. Per process, not per connection: a relay that drops a
// connection must not get a fresh key (and an empty register) from the redial.
var processA2AE2EEStatic = sync.OnceValues(func() (*a2aE2EEStatic, error) { return newA2AE2EEStatic(rand.Reader) })

// label is the A2AE2EEStaticLabel value: the key, and with a pairing key a
// tag binding it and this agent's name to the key.
func (st *a2aE2EEStatic) label(name string, pairing []byte) string {
	s := a2aE2EEB64.EncodeToString(st.key.Public)
	if pairing == nil {
		return s
	}
	return s + "." + a2aE2EEB64.EncodeToString(a2aE2EEPairingTag(pairing, "static", name, st.key.Public)) + "." + name
}

// parseA2AE2EEStaticLabel is the peer key a label offers this initiator, and
// with a pairing key the peer name its tag proves; ok is false when the
// initiator must take the interactive handshake instead.
func parseA2AE2EEStaticLabel(v string, pairing []byte) (static []byte, name string, ok bool) {
	parts := strings.SplitN(v, ".", 3)
	s, err := a2aE2EEB64.DecodeString(parts[0])
	if err != nil || len(s) != a2aE2EEPubLen {
		return nil, "", false
	}
	if pairing == nil {
		return s, "", len(parts) == 1
	}
	if len(parts) != 3 {
		return nil, "", false
	}
	tag, err := a2aE2EEB64.DecodeString(parts[1])
	if err != nil || !hmac.Equal(tag, a2aE2EEPairingTag(pairing, "static", parts[2], s)) {
		return nil, "", false
	}
	return s, parts[2], true
}

// The peers' advertised keys this process has seen, by agent id.
var a2aE2EEPeers struct {
	mu sync.Mutex
	m  map[string]string
}

// a2aE2EEPeersMax bounds the book.
const a2aE2EEPeersMax = 4096

// LearnA2AE2EEPeer records the A2A E2EE static key agentID advertises in its
// connect labels (as a relay agent list or presence arrival shows them), so
// this process's next E2EE call to it sends its first request at once (0-RTT)
// instead of after a handshake round trip; labels without one forget it. A
// stale key costs one extra round trip, never the call.
func LearnA2AE2EEPeer(agentID string, labels map[string]string) {
	v := labels[A2AE2EEStaticLabel]
	a2aE2EEPeers.mu.Lock()
	defer a2aE2EEPeers.mu.Unlock()
	if v == "" {
		delete(a2aE2EEPeers.m, agentID)
		return
	}
	if a2aE2EEPeers.m == nil || len(a2aE2EEPeers.m) >= a2aE2EEPeersMax {
		// ponytail: drops the whole book when full; an LRU if a process ever calls more agents than this.
		a2aE2EEPeers.m = map[string]string{}
	}
	a2aE2EEPeers.m[agentID] = v
}

func a2aE2EEPeer(agentID string) string {
	a2aE2EEPeers.mu.Lock()
	defer a2aE2EEPeers.mu.Unlock()
	return a2aE2EEPeers.m[agentID]
}

// forgetA2AE2EEPeer drops agentID's key if it is still v (a refused stale key).
func forgetA2AE2EEPeer(agentID, v string) {
	a2aE2EEPeers.mu.Lock()
	defer a2aE2EEPeers.mu.Unlock()
	if a2aE2EEPeers.m[agentID] == v {
		delete(a2aE2EEPeers.m, agentID)
	}
}

func a2aE2EE0RTTPSK(pairing []byte) []byte {
	if pairing == nil {
		return nil
	}
	return a2aE2EEPairingTag(pairing, "0rtt-psk", "")
}

// a2aE2EE0RTTHandshake is one end of Noise NK (NKpsk0 with a pairing key);
// the prologue binds the txn id, the version and the timestamp.
func a2aE2EE0RTTHandshake(initiator bool, txnID string, head, pairing []byte, static noise.DHKey, peerStatic []byte, rng io.Reader) (*noise.HandshakeState, error) {
	prologue := append(append(append(append([]byte(a2aE2EE0RTTContext), 0), txnID...), 0), head...)
	cfg := noise.Config{CipherSuite: a2aE2EESuite, Pattern: noise.HandshakeNK, Initiator: initiator, Prologue: prologue, Random: rng}
	if psk := a2aE2EE0RTTPSK(pairing); psk != nil {
		cfg.PresharedKey, cfg.PresharedKeyPlacement = psk, 0
	}
	if initiator {
		cfg.PeerStatic = peerStatic
	} else {
		cfg.StaticKeypair = static
	}
	return noise.NewHandshakeState(cfg)
}

// firstFlight builds the a2a-e2ee-init-0rtt payload carrying data, when this
// call knows the peer's static key and has sent nothing yet; ok is false
// otherwise (the call takes the interactive handshake).
func (s *a2aE2EEState) firstFlight(data []byte, now time.Time, rng io.Reader) (payload []byte, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.peerStatic == nil {
		return nil, false, nil
	}
	head := make([]byte, a2aE2EE0RTTHeadLen)
	head[0] = a2aE2EE0RTTVersion
	binary.BigEndian.PutUint64(head[1:], uint64(now.UnixMilli()))
	hs, err := a2aE2EE0RTTHandshake(true, s.txnID, head, s.pairing, noise.DHKey{}, s.peerStatic, rng)
	if err != nil {
		return nil, true, fmt.Errorf("rpcclient: A2A E2EE 0-RTT handshake: %w", err)
	}
	earlyKey := make([]byte, 32)
	if _, err := io.ReadFull(rng, earlyKey); err != nil {
		return nil, true, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, earlyKey)
	if err != nil {
		return nil, true, fmt.Errorf("rpcclient: A2A E2EE 0-RTT first message: %w", err)
	}
	sealed, err := a2aE2EESeal(earlyKey, rng, s.txnID, data)
	if err != nil {
		return nil, true, err
	}
	s.started, s.hs, s.sentAt = true, hs, now
	s.eph = append([]byte(nil), msg1[:a2aE2EEPubLen]...)
	s.early = append([]byte(nil), data...)
	payload = append(append(append(head, s.peerStatic...), msg1...), sealed...)
	return payload, true, nil
}

// completeZeroRTT reads the responder's message 2: the call's keys.
func (s *a2aE2EEState) completeZeroRTT(hs *noise.HandshakeState, msg2 []byte) error {
	out, c1, c2, err := hs.ReadMessage(nil, msg2)
	if err == nil && (len(out) != 0 || c1 == nil) {
		err = errors.New("unexpected handshake message")
	}
	if err != nil {
		err = fmt.Errorf("rpcclient: A2A E2EE 0-RTT ack failed verification (a relay in the middle, or a different pairing key); %s: %w", a2aE2EEPairingRemedy, errA2AE2EEPairing)
		s.fail(err)
		return err
	}
	send, recv := c1.UnsafeKey(), c2.UnsafeKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.key, s.recvKey, s.ready, s.hs, s.early = send[:], recv[:], true, nil, nil
	if s.waitCh != nil {
		close(s.waitCh)
		s.waitCh = nil
	}
	return nil
}

// a2aE2EEAccepted is a first flight a responder took.
type a2aE2EEAccepted struct {
	state   *a2aE2EEState
	ack     []byte // Noise message 2
	request []byte // the call's first request
}

// accept takes or refuses a first flight; e is its ephemeral key when the
// payload was long enough to carry one (a refusal's tag binds it).
func (st *a2aE2EEStatic) accept(pairing []byte, txnID string, payload []byte, now time.Time, rng io.Reader) (acc a2aE2EEAccepted, e []byte, refusal a2aE2EERefusal) {
	if len(payload) < a2aE2EE0RTTMinLen {
		return acc, nil, refuseBad
	}
	head, rs := payload[:a2aE2EE0RTTHeadLen], payload[a2aE2EE0RTTHeadLen:a2aE2EE0RTTHeadLen+a2aE2EEPubLen]
	msg1 := payload[a2aE2EE0RTTHeadLen+a2aE2EEPubLen : a2aE2EE0RTTHeadLen+a2aE2EEPubLen+a2aE2EE0RTTMsg1Len]
	sealed := payload[a2aE2EE0RTTHeadLen+a2aE2EEPubLen+a2aE2EE0RTTMsg1Len:]
	e = msg1[:a2aE2EEPubLen]
	// Every ephemeral key is burned before anything else is judged: a
	// flight refused now (and so retried interactively) can never be taken
	// later, and a copy of a taken flight always reads replay.
	if r := st.burn(e, now); r != 0 {
		return acc, e, r
	}
	if head[0] != a2aE2EE0RTTVersion {
		return acc, e, refuseBad
	}
	if !bytes.Equal(rs, st.key.Public) {
		return acc, e, refuseStale
	}
	sent := time.UnixMilli(int64(binary.BigEndian.Uint64(head[1:]))) // #nosec G115 -- any value: one outside the window is refused
	if d := now.Sub(sent); d > a2aE2EE0RTTWindow || d < -a2aE2EE0RTTWindow {
		return acc, e, refuseClock
	}
	hs, err := a2aE2EE0RTTHandshake(false, txnID, head, pairing, st.key, nil, rng)
	if err != nil {
		return acc, e, refuseBad
	}
	earlyKey, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil || len(earlyKey) != 32 {
		return acc, e, refuseBad
	}
	request, err := a2aE2EEOpen(earlyKey, txnID, sealed)
	if err != nil {
		return acc, e, refuseBad
	}
	ack, c1, c2, err := hs.WriteMessage(nil, nil)
	if err != nil || c1 == nil {
		return acc, e, refuseBad
	}
	recv, send := c1.UnsafeKey(), c2.UnsafeKey()
	state := newEstablishedA2AE2EEState(send[:])
	state.recvKey = recv[:]
	return a2aE2EEAccepted{state: state, ack: ack, request: request}, e, 0
}

// burn records e in the replay register until no flight carrying it can be
// taken (2 windows: the timestamp may lead this clock by one); replay when
// it is there, busy when the register is full (and then for 2 windows, so a
// flight refused busy can never be taken later either).
func (st *a2aE2EEStatic) burn(e []byte, now time.Time) a2aE2EERefusal {
	k := [a2aE2EEPubLen]byte(e)
	st.mu.Lock()
	defer st.mu.Unlock()
	if until, ok := st.seen[k]; ok && now.Before(until) {
		return refuseReplay
	}
	if now.Before(st.fullUntil) {
		return refuseBusy
	}
	if len(st.seen) >= a2aE2EE0RTTSeenMax {
		for x, until := range st.seen {
			if !now.Before(until) {
				delete(st.seen, x)
			}
		}
		if len(st.seen) >= a2aE2EE0RTTSeenMax {
			st.fullUntil = now.Add(2 * a2aE2EE0RTTWindow)
			return refuseBusy
		}
	}
	st.seen[k] = now.Add(2 * a2aE2EE0RTTWindow)
	return 0
}

// retryPayload is a refusal: the reason and, with a pairing key, a tag
// binding it to this call, the refused ephemeral key and this agent's name.
func retryPayload(pairing []byte, name, txnID string, e []byte, r a2aE2EERefusal) []byte {
	out := []byte{byte(r)}
	if pairing != nil {
		out = append(out, a2aE2EEPairingTag(pairing, "retry", txnID, e, out, []byte(name))...)
	}
	return out
}

// takeRetry judges a refusal of this call's first flight: inner is the
// interactive handshake to run instead and early the request to re-send.
// A frame that is no refusal of a flight this call is waiting on is
// ignored (nil, nil, nil); a refusal it must not retry is an error.
func (s *a2aE2EEState) takeRetry(payload []byte, now time.Time) (inner *a2aE2EEState, early []byte, reason a2aE2EERefusal, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hs == nil || s.ready || s.err != nil || now.Sub(s.sentAt) > a2aE2EEHandshakeTimeout || len(payload) == 0 {
		return nil, nil, 0, nil
	}
	reason = a2aE2EERefusal(payload[0])
	if s.pairing != nil {
		want := a2aE2EEPairingTag(s.pairing, "retry", s.txnID, s.eph, payload[:1], []byte(s.peerName))
		if !hmac.Equal(payload[1:], want) {
			return nil, nil, reason, fmt.Errorf("rpcclient: peer's A2A E2EE 0-RTT refusal failed pairing-key verification (a relay in the middle, or another agent); %s: %w", a2aE2EEPairingRemedy, errA2AE2EEPairing)
		}
	}
	if reason == refuseReplay || reason < refuseStale || reason > refuseReplay {
		return nil, nil, reason, fmt.Errorf("rpcclient: peer refused this call's A2A E2EE first flight (reason %d: a replayed flight)", reason)
	}
	inner = newA2AE2EEState(s.txnID, s.pairing)
	early, s.inner, s.hs, s.early = s.early, inner, nil, nil
	return inner, early, reason, nil
}

// adopt takes the keys of the interactive handshake run after a refusal.
func (s *a2aE2EEState) adopt(inner *a2aE2EEState) error {
	key := inner.readyKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.key, s.recvKey, s.ready, s.inner = key, nil, true, nil
	if s.waitCh != nil {
		close(s.waitCh)
		s.waitCh = nil
	}
	return nil
}
