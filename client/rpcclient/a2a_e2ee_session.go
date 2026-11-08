// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// A2A E2EE sessions (spec/proverif/a2a_machine.pv "Sessions",
// spec/A2ASession.tla; nfltr docs/decisions/a2a-machine-identity-2026-11-07.md
// "Session reuse"): a keyed wire v2 handshake leaves both ends a session
// secret; a later call between the same caller and callee skips the
// handshake. Its resume names the session and a call number never used on
// it before, authenticated by the secret; the call's keys are derived from
// the secret, its txn, its call number and the direction, so no key (and so
// no nonce) is ever used by two calls.

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const (
	a2aE2EEResumeMessageType  = "a2a-e2ee-v2-resume"
	a2aE2EEResumedMessageType = "a2a-e2ee-v2-resumed"
	a2aE2EEUnknownMessageType = "a2a-e2ee-v2-unknown"
	// a2aE2EEWarmMessageType is an init with no call (WarmA2AE2EE): the
	// callee answers it with its ack and keeps the session, starting no
	// handler; both frames end the route (Eom).
	a2aE2EEWarmMessageType = "a2a-e2ee-v2-warm"

	a2aSessionLabel   = "nfltr-a2a-e2ee-v2-session"
	a2aSessionIDLabel = "nfltr-a2a-e2ee-v2-sid"
	a2aResumeLabel    = "nfltr-a2a-e2ee-v2-resume"
	a2aCallLabel      = "nfltr-a2a-e2ee-v2-call"

	a2aSessionIDLen = 16
	a2aResumeLen    = a2aSessionIDLen + 8 + sha256.Size
	a2aRetryLen     = a2aSessionIDLen + 8 + 8

	// a2aSessionIdle: a caller drops a session idle this long; a callee
	// keeps it a while longer, so a resume rarely finds it gone.
	a2aSessionIdle       = 10 * time.Minute
	a2aSessionCalleeIdle = a2aSessionIdle + 5*time.Minute
	a2aSessionMaxAge     = 24 * time.Hour
	a2aSessionMaxCalls   = 1 << 32
	a2aSessionMax        = 1024 // per agent and side
	a2aReplayWindow      = 256  // call numbers below the highest one a callee still takes

	// a2aRetryBound: the handshake after an unknown (a retry) names a
	// resume taken at most this long ago, by either end's clock. A callee
	// keeps a session a2aSessionCalleeIdle > 2 * a2aRetryBound past its
	// last call, so with clocks less than a2aRetryBound apart a callee
	// that no longer knows a retried session lost it to a restart
	// (spec/A2ASession.tla RetryOK, ExpireCallee).
	a2aRetryBound = 5 * time.Minute
)

// a2aSessionOffer is the ack's payload (sealed in Noise message 2): the
// callee keeps the handshake as a session. An older callee's empty payload
// keeps the caller handshaking every call.
var a2aSessionOffer = []byte{1}

// a2aSession is one end's session with a peer.
type a2aSession struct {
	id             [a2aSessionIDLen]byte
	secret         []byte
	caller, callee string
	kid            string
	keyFP          [sha256.Size]byte // the key the handshake used
	created, used  time.Time

	next uint64              // caller: the next call number (1, 2, ...)
	seen map[uint64]struct{} // callee: call numbers taken above the window's floor
	max  uint64              // callee: the highest call number taken
}

// newA2ASession makes the session of a handshake from its transport keys
// (initiator to responder, responder to initiator).
func newA2ASession(i2r, r2i *noise.CipherState, caller, callee, kid string, keyFP [sha256.Size]byte, now time.Time) *a2aSession {
	ki, kr := i2r.UnsafeKey(), r2i.UnsafeKey()
	secret, err := hkdf.Key(sha256.New, append(ki[:], kr[:]...), nil, a2aSessionLabel, 32)
	if err != nil {
		panic(err) // a 32-byte SHA-256 HKDF output never fails
	}
	s := &a2aSession{secret: secret, caller: caller, callee: callee, kid: kid, keyFP: keyFP, created: now, used: now, next: 1}
	copy(s.id[:], a2aMAC(secret, []byte(a2aSessionIDLabel)))
	return s
}

func a2aMAC(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// a2aCallField is label 0 txn 0 c (8 bytes, big endian): txn holds no 0
// byte (a2aE2EEFieldsOK), so it is injective.
func a2aCallField(label, txnID string, c uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte(label+"\x00"+txnID+"\x00"), c)
}

// resumeTag is HMAC(S, resume label 0 txn 0 c) (model rtag(S, t, c)).
func (s *a2aSession) resumeTag(txnID string, c uint64) []byte {
	return a2aMAC(s.secret, a2aCallField(a2aResumeLabel, txnID, c))
}

// callKeys are call c's keys, initiator to responder and back (model
// callk(S, t, c, dir)): HKDF(S, call label 0 txn 0 c 0 direction).
func (s *a2aSession) callKeys(txnID string, c uint64) (i2r, r2i *a2aCallCipher) {
	key := func(dir string) *a2aCallCipher {
		k, err := hkdf.Key(sha256.New, s.secret, nil, string(append(a2aCallField(a2aCallLabel, txnID, c), "\x00"+dir...)), 32)
		if err != nil {
			panic(err)
		}
		return &a2aCallCipher{c: a2aE2EESuite.Cipher([32]byte(k))}
	}
	return key("i2r"), key("r2i")
}

// a2aCallCipher is one direction of a resumed call: its own key, a 64-bit
// counter nonce from 0 (Noise's AESGCM nonce), as noise.CipherState.
type a2aCallCipher struct {
	c noise.Cipher
	n uint64
}

var errA2ANoncesSpent = errors.New("rpcclient: an A2A E2EE call used every nonce of its key")

func (k *a2aCallCipher) Encrypt(out, ad, plaintext []byte) ([]byte, error) {
	if k.n == math.MaxUint64 {
		return nil, errA2ANoncesSpent
	}
	ct := k.c.Encrypt(out, k.n, ad, plaintext)
	k.n++
	return ct, nil
}

func (k *a2aCallCipher) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
	if k.n == math.MaxUint64 {
		return nil, errA2ANoncesSpent
	}
	pt, err := k.c.Decrypt(out, k.n, ad, ciphertext)
	if err != nil {
		return nil, err
	}
	k.n++
	return pt, nil
}

// a2aSessions is an agent's sessions: as caller by the callee ref, as
// callee by session id. Memory only: a restart loses them (and with them
// every key derived from them).
type a2aSessions struct {
	mu  sync.Mutex
	out map[string]*a2aSession
	in  map[[a2aSessionIDLen]byte]*a2aSession
	now func() time.Time // tests
}

func (ss *a2aSessions) clock() time.Time {
	if ss.now != nil {
		return ss.now()
	}
	return time.Now()
}

func (s *a2aSession) expired(now time.Time, idle time.Duration) bool {
	return now.Sub(s.used) > idle || now.Sub(s.created) > a2aSessionMaxAge
}

// keyHolds reports whether the keyring still gives the session's key for
// ref: not revoked, not rotated to another generation.
func (s *a2aSession) keyHolds(kr A2AE2EEKeyring, ref string) bool {
	if !kr.Valid(s.kid) {
		return false
	}
	kid, key, err := kr.For(ref)
	return err == nil && kid == s.kid && sha256.Sum256(key) == s.keyFP
}

// evict makes room for one more session in m: expired ones go, then the
// least recently used.
// ponytail: O(n) scan per insert into a full map (n <= a2aSessionMax); an LRU list if that shows.
func evictA2ASession[K comparable](m map[K]*a2aSession, now time.Time, idle time.Duration) {
	if len(m) < a2aSessionMax {
		return
	}
	var oldest K
	var found bool
	for k, s := range m {
		if s.expired(now, idle) {
			delete(m, k)
			continue
		}
		if !found || s.used.Before(m[oldest].used) {
			oldest, found = k, true
		}
	}
	if len(m) >= a2aSessionMax && found {
		delete(m, oldest)
	}
}

// putOut keeps a caller's session with callee (a later handshake replaces
// an earlier one).
func (ss *a2aSessions) putOut(callee string, s *a2aSession) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.out == nil {
		ss.out = map[string]*a2aSession{}
	}
	if _, ok := ss.out[callee]; !ok {
		evictA2ASession(ss.out, ss.clock(), a2aSessionIdle)
	}
	ss.out[callee] = s
}

// hasOut reports whether the caller keeps a session with callee whose key
// still holds.
func (ss *a2aSessions) hasOut(callee string, kr A2AE2EEKeyring) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s := ss.out[callee]
	return s != nil && !s.expired(ss.clock(), a2aSessionIdle) && s.next < a2aSessionMaxCalls && s.keyHolds(kr, callee)
}

// putIn keeps a callee's session.
func (ss *a2aSessions) putIn(s *a2aSession) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.in == nil {
		ss.in = map[[a2aSessionIDLen]byte]*a2aSession{}
	}
	evictA2ASession(ss.in, ss.clock(), a2aSessionCalleeIdle)
	ss.in[s.id] = s
}

// takeCall gives a call to callee its session and a call number never
// used on it, or nil: no session, or one that expired or whose key no
// longer holds (it is dropped: the call handshakes).
func (ss *a2aSessions) takeCall(callee string, kr A2AE2EEKeyring) (*a2aSession, uint64) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s := ss.out[callee]
	if s == nil {
		return nil, 0
	}
	now := ss.clock()
	if s.expired(now, a2aSessionIdle) || s.next >= a2aSessionMaxCalls || !s.keyHolds(kr, callee) {
		delete(ss.out, callee)
		return nil, 0
	}
	c := s.next
	s.next++
	s.used = now
	return s, c
}

// dropOut forgets the caller's session with callee if it is s.
func (ss *a2aSessions) dropOut(callee string, s *a2aSession) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.out[callee] == s {
		delete(ss.out, callee)
	}
}

// resumeMessage is sid ‖ c ‖ tag.
func (s *a2aSession) resumeMessage(txnID string, c uint64) []byte {
	msg := binary.BigEndian.AppendUint64(append([]byte(nil), s.id[:]...), c)
	return append(msg, s.resumeTag(txnID, c)...)
}

// errA2ASessionUnknown: a resume the callee does not take (no such
// session, expired, a key that no longer holds, a call number taken or
// below the window); the caller handshakes.
var errA2ASessionUnknown = errors.New("rpcclient: A2A E2EE session unknown")

// resume takes a resume of call txnID: its session and call number, or
// errA2ASessionUnknown. A session whose key no longer holds is dropped.
func (ss *a2aSessions) resume(txnID string, msg []byte, kr A2AE2EEKeyring) (*a2aSession, uint64, error) {
	if len(msg) != a2aResumeLen {
		return nil, 0, errA2ASessionUnknown
	}
	id := [a2aSessionIDLen]byte(msg[:a2aSessionIDLen])
	c := binary.BigEndian.Uint64(msg[a2aSessionIDLen:])
	tag := msg[a2aSessionIDLen+8:]
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s := ss.in[id]
	if s == nil {
		return nil, 0, errA2ASessionUnknown
	}
	now := ss.clock()
	if !hmac.Equal(tag, s.resumeTag(txnID, c)) {
		return nil, 0, errA2ASessionUnknown // not the caller's: the session stays
	}
	if s.expired(now, a2aSessionCalleeIdle) || !s.keyHolds(kr, s.caller) {
		delete(ss.in, id)
		return nil, 0, errA2ASessionUnknown
	}
	if !s.takeCallNumber(c) {
		return nil, 0, errA2ASessionUnknown
	}
	s.used = now
	return s, c, nil
}

// takeCallNumber is the callee's replay window: c is taken once, and only
// above max - a2aReplayWindow (spec/A2ASession.tla AtMostOnce).
// ponytail: a map of at most a2aReplayWindow numbers, pruned when max moves; a bitmap if it shows.
func (s *a2aSession) takeCallNumber(c uint64) bool {
	if c == 0 || (s.max > a2aReplayWindow && c <= s.max-a2aReplayWindow) {
		return false
	}
	if _, dup := s.seen[c]; dup {
		return false
	}
	if s.seen == nil {
		s.seen = map[uint64]struct{}{}
	}
	s.seen[c] = struct{}{}
	if c > s.max {
		s.max = c
		for n := range s.seen {
			if s.max > a2aReplayWindow && n <= s.max-a2aReplayWindow {
				delete(s.seen, n)
			}
		}
	}
	return true
}

// retryMessage is sid ‖ c ‖ when c was taken (unix ms): the payload of a
// retry's Noise message 1, sealed under the pairing key.
func (s *a2aSession) retryMessage(c uint64, at time.Time) []byte {
	msg := binary.BigEndian.AppendUint64(append([]byte(nil), s.id[:]...), c)
	return binary.BigEndian.AppendUint64(msg, uint64(at.UnixMilli()))
}

// errA2ARetryRefused: a callee refuses a retry of a resume it took (the
// unknown the caller got was not the callee's: the call may have run), of
// another pair's session, or past a2aRetryBound.
var errA2ARetryRefused = errors.New("rpcclient: A2A E2EE retry refused: the callee took the call it retries (an unknown not from the callee: the call may have run), or the retry is past its bound")

// retry answers a retry by caller under kid: within a2aRetryBound, and a
// call number its session (when this agent still keeps it) has not taken;
// it takes the number, so the resume, delivered later, is refused
// (spec/A2ASession.tla Unknown).
func (ss *a2aSessions) retry(msg []byte, caller, kid string) error {
	if len(msg) != a2aRetryLen {
		return errA2ARetryRefused
	}
	id := [a2aSessionIDLen]byte(msg[:a2aSessionIDLen])
	c := binary.BigEndian.Uint64(msg[a2aSessionIDLen:])
	at := time.UnixMilli(int64(binary.BigEndian.Uint64(msg[a2aSessionIDLen+8:]))) // #nosec G115 -- a wrapped value is a time outside a2aRetryBound, refused below
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if d := ss.clock().Sub(at); d > a2aRetryBound || d < -a2aRetryBound {
		return errA2ARetryRefused
	}
	s := ss.in[id]
	if s == nil {
		return nil // lost to a restart: nothing of it ran here
	}
	if s.caller != caller || s.kid != kid || !s.takeCallNumber(c) {
		return errA2ARetryRefused
	}
	return nil
}

// a2aSentFrame is a frame a resumed call sent before its callee took the
// resume, kept to send again after a handshake.
type a2aSentFrame struct {
	t    byte
	body []byte
}

// newResumedA2AE2EEState is the caller's state of call c on session s: its
// keys at once, the resume to send first.
func newResumedA2AE2EEState(txnID string, s *a2aSession, c uint64, kr A2AE2EEKeyring) *a2aE2EEState {
	i2r, r2i := s.callKeys(txnID, c)
	st := newA2AE2EEState(txnID, s.caller, s.callee, kr)
	st.kid, st.send, st.recv, st.ready = s.kid, i2r, r2i, true
	st.session, st.resume, st.retry = s, s.resumeMessage(txnID, c), s.retryMessage(c, time.Now())
	st.confirmed = make(chan struct{})
	return st
}

// newResumedServerA2AE2EEState is the callee's state of call c on s.
func newResumedServerA2AE2EEState(txnID string, s *a2aSession, c uint64, kr A2AE2EEKeyring) *a2aE2EEState {
	i2r, r2i := s.callKeys(txnID, c)
	return &a2aE2EEState{started: true, ready: true, txnID: txnID, caller: s.caller, callee: s.callee, kr: kr, kid: s.kid, send: r2i, recv: i2r}
}

// resuming reports whether the call is a resume its callee has not yet
// answered.
func (s *a2aE2EEState) resuming() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmed != nil && s.resume != nil && !s.isConfirmed()
}

func (s *a2aE2EEState) isConfirmed() bool {
	select {
	case <-s.confirmed:
		return true
	default:
		return false
	}
}

// keep records a frame sent while resuming (sealed under s.mu by the caller).
func (s *a2aE2EEState) keep(t byte, body []byte) {
	if s.confirmed != nil && s.resume != nil && !s.isConfirmed() {
		s.sent = append(s.sent, a2aSentFrame{t: t, body: bytes.Clone(body)})
	}
}

// confirm: the callee took the resume (or the handshake after its refusal
// completed): the kept frames go.
func (s *a2aE2EEState) confirm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.confirmed != nil && !s.isConfirmed() {
		close(s.confirmed)
	}
	s.sent = nil
}

// restart turns a refused resume into a fresh handshake on the same call,
// naming the resume it retries (retry), and gives the frames to send
// again; once per call.
func (s *a2aE2EEState) restart() ([]a2aSentFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resume == nil || s.isConfirmed() || s.err != nil || s.broken != nil {
		return nil, errors.New("rpcclient: an A2A E2EE session refusal out of place (not from the callee: the relay); the call ends")
	}
	sent := s.sent
	s.sent, s.resume = nil, nil // s.retry stays: initMessage sends it
	s.started, s.ready, s.send, s.recv, s.kid = false, false, nil, nil, ""
	s.waitCh = make(chan struct{})
	return sent, nil
}
