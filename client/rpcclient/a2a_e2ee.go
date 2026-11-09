// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// A2A E2EE wire v2 (spec/proverif/a2a_machine.pv; nfltr
// docs/decisions/a2a-machine-identity-2026-11-07.md "Wire v2"): an
// interactive Noise handshake bound to the call's txn, both agent refs and
// the key id, then one Noise transport key per direction with counter
// nonces; every frame's plaintext is a type byte and a body, so the end of a
// stream and an error are the peer's.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"sync"
	"time"

	"github.com/flynn/noise"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	a2aE2EEInitMessageType = "a2a-e2ee-v2-init"
	a2aE2EEAckMessageType  = "a2a-e2ee-v2-ack"

	// Wire v1's handshake frames: refused, naming the upgrade.
	a2aE2EEv1InitMessageType     = "a2a-e2ee-init"
	a2aE2EEv1Init0RTTMessageType = "a2a-e2ee-init-0rtt"
	a2aE2EEv1AckMessageType      = "a2a-e2ee-ack"
	a2aE2EEv1RetryMessageType    = "a2a-e2ee-retry"
	a2aE2EEv1Refusal             = "A2A E2EE wire v1 is not supported: upgrade the peer to an nfltr with wire v2"

	// a2aE2EEHandshakeTimeout caps how long the initiator waits for the peer
	// to complete the key exchange. If the peer disconnects without responding
	// the caller can retry rather than waiting for the full task timeout.
	a2aE2EEHandshakeTimeout = 30 * time.Second

	a2aE2EEHeaderKey  = "x-a2a-e2ee"
	a2aE2EECipherKey  = "x-a2a-e2ee-cipher"
	a2aE2EECipherName = "noise-psk-aesgcm-sha256-v2"

	a2aE2EEProtocol = "nfltr-a2a-e2ee-v2"     // the prologue's first field
	a2aE2EEPskLabel = "nfltr-a2a-e2ee-v2-psk" // psk = HMAC(K_kid, label)

	a2aE2EEKeyedMsg1Len      = 32 + 16 // message 1 (NNpsk0: psk, e): an X25519 key and the empty payload's tag
	a2aWarmMark              = "W"     // a warm's message 1 payload (a call's is empty or a retry): its AEAD binds the type
	a2aE2EEPairingMinSecret  = 32
	a2aE2EEPairingRemedy     = "set the same --e2ee-key-file / NFLTR_A2A_E2EE_KEY_FILE on both ends"
	a2aE2EEPairingKeyContext = "nfltr-a2a-e2ee-pairing-v1"
	a2aE2EEKeyIDMax          = 128
	a2aE2EERefMax            = 512
)

// Frame plaintext types (the first byte of every sealed frame).
const (
	a2aFrameData  byte = 1
	a2aFrameEnd   byte = 2
	a2aFrameError byte = 3 // body: 4-byte big-endian gRPC code, then the detail
	// a2aFrameHeader is a callee's first data frame: its response headers
	// (SetHeader) sealed with the data, so they are the callee's. Body:
	// uvarint length, the headers as JSON, then the data.
	a2aFrameHeader byte = 4
)

// a2aHeaderBody is the body of a header frame: md, then data.
func a2aHeaderBody(md MD, data []byte) ([]byte, error) {
	enc, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}
	return append(append(binary.AppendUvarint(nil, uint64(len(enc))), enc...), data...), nil
}

// parseA2AHeaderBody is a2aHeaderBody's inverse.
func parseA2AHeaderBody(body []byte) (MD, []byte, error) {
	n, w := binary.Uvarint(body)
	if w <= 0 || n > uint64(len(body)-w) { // #nosec G115 -- 0 < w <= len(body)
		return nil, nil, errors.New("rpcclient: a malformed A2A E2EE header frame")
	}
	var md MD
	if err := json.Unmarshal(body[w:w+int(n)], &md); err != nil { // #nosec G115 -- n <= len(body)
		return nil, nil, fmt.Errorf("rpcclient: a malformed A2A E2EE header frame: %w", err)
	}
	return md, body[w+int(n):], nil // #nosec G115 -- n <= len(body)
}

var a2aE2EESuite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

// A2AE2EEKeyring is one end's A2A E2EE keys (WithA2AE2EEKeyring). A key id
// names a key: "" is the root pairing key (LoadA2AE2EEPairingKey), which
// every root holder has; any other id is a machine key the caller manages
// (nfltr derives one per machine from the root key,
// docs/decisions/a2a-machine-identity-2026-11-07.md).
//
// For gives the key of a call with the agent ref ref: a caller asks it for
// the agent it calls and seals the handshake under that key id; a callee
// asks it for the caller's ref and answers only when the caller's key id is
// that one. A machine's keyring answers its own key for every ref (it talks
// to root holders only); a root holder's answers the machine key of the
// ref's machine, refusing a revoked or unknown one, or "" for a root
// holder. The relay never chooses the key id.
type A2AE2EEKeyring interface {
	// For is the key id and key of a call with ref; an error refuses the
	// call before any key is used.
	For(ref string) (id string, key []byte, err error)
	// Valid reports whether an established call's key id still holds. It is
	// asked before each later frame of the call is sealed or opened, so a
	// revoke ends calls in flight at their next frame, and by
	// RecheckA2AE2EE, which ends them at once.
	Valid(id string) bool
	// Machine reports whether this end is a machine (one machine key, no
	// root key). The handshake binds the initiator's role: a machine
	// answers root holders only, so a relay that returns a machine's call
	// to that machine or another agent of it is refused (a2aE2EERole).
	Machine() bool
}

// A2AE2EEKeyringChanges is a keyring that says when its keys may have
// changed (a store a revoke rewrites): an agent keyed by one runs
// RecheckA2AE2EE after each change, so a revoke ends its calls in flight at
// once, not at their next frame.
type A2AE2EEKeyringChanges interface {
	A2AE2EEKeyring
	// OnChange calls changed after each change until ctx ends; it does
	// not block.
	OnChange(ctx context.Context, changed func())
}

// a2aE2EEPairingKey is the keyring of a root pairing key alone: id "" only.
type a2aE2EEPairingKey []byte

func (k a2aE2EEPairingKey) For(string) (string, []byte, error) { return "", k, nil }

func (k a2aE2EEPairingKey) Valid(id string) bool { return id == "" }

func (a2aE2EEPairingKey) Machine() bool { return false }

// The initiator's role in the prologue (model ROLER, ROLEM).
const (
	a2aE2EERoleRoot    = "root"
	a2aE2EERoleMachine = "machine"
)

// a2aE2EERole is the role of the initiator of a call sealed under key id
// kid at the end whose keyring is kr: the initiator's own role (initiator
// true), or the one a responder answers (false). A machine calls as a
// machine and answers root holders only; a root holder calls as root and
// answers a machine key id from a machine, the root key ("") from a root
// holder.
func a2aE2EERole(kr A2AE2EEKeyring, kid string, initiator bool) string {
	machine := kr.Machine()
	switch {
	case initiator && machine, !initiator && !machine && kid != "":
		return a2aE2EERoleMachine
	default:
		return a2aE2EERoleRoot
	}
}

// errA2AE2EEPairing marks a handshake refused because a peer did not prove
// the key its call needs.
var errA2AE2EEPairing = errors.New("A2A E2EE pairing key")

// ErrA2AE2EENoKey refuses A2A E2EE without a key: it is keyed only (nfltr
// docs/decisions/a2a-machine-identity-2026-11-07.md "Keyed only"). Dial
// returns it for WithA2AE2EE without WithA2AE2EEKeyring or
// WithA2AE2EEPairingKeyFile; an agent without keys refuses every E2EE call.
var ErrA2AE2EENoKey = errors.New("rpcclient: A2A E2EE needs a key (WithA2AE2EEKeyring or WithA2AE2EEPairingKeyFile); there is no unkeyed A2A E2EE")

// LoadA2AE2EEPairingKey reads a pairing key file and derives the 32-byte key
// K = SHA-256(context ‖ secret). The secret must be random: a relay that
// sees handshakes could test guesses of a short passphrase offline. nfltr
// p2p uses the same key (p2p.NewE2E).
func LoadA2AE2EEPairingKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: read A2A E2EE pairing key file: %w", err)
	}
	secret := bytes.TrimSpace(raw)
	if len(secret) < a2aE2EEPairingMinSecret {
		return nil, fmt.Errorf("rpcclient: A2A E2EE pairing key file %s holds %d bytes; want at least %d bytes of random secret (e.g. openssl rand -hex 32)", path, len(secret), a2aE2EEPairingMinSecret)
	}
	sum := sha256.Sum256(append([]byte(a2aE2EEPairingKeyContext), secret...))
	return sum[:], nil
}

// a2aE2EEPsk is the Noise psk of the key a key id names (model: psk(K)).
func a2aE2EEPsk(key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(a2aE2EEPskLabel))
	return m.Sum(nil)
}

// a2aE2EEPrologue is v2 0 txn 0 role 0 caller 0 callee 0 key id (model:
// prologue(t, r, caller, callee, k)); no field holds a 0 byte, so it is
// injective. The role is the initiator's (a2aE2EERole); it is not sent:
// each end puts the one it expects, so a mismatch fails message 1.
func a2aE2EEPrologue(txnID, role, caller, callee, kid string) []byte {
	return []byte(a2aE2EEProtocol + "\x00" + txnID + "\x00" + role + "\x00" + caller + "\x00" + callee + "\x00" + kid)
}

// a2aE2EEFieldsOK reports whether the handshake's fields fit the prologue.
func a2aE2EEFieldsOK(txnID, caller, callee, kid string) error {
	for _, f := range []string{txnID, caller, callee, kid} {
		if bytes.IndexByte([]byte(f), 0) >= 0 {
			return errors.New("rpcclient: an A2A E2EE handshake field holds a 0 byte")
		}
	}
	if len(kid) > a2aE2EEKeyIDMax {
		return fmt.Errorf("rpcclient: A2A E2EE key id is longer than %d bytes: %w", a2aE2EEKeyIDMax, errA2AE2EEPairing)
	}
	if len(caller) > a2aE2EERefMax || len(callee) > a2aE2EERefMax || len(txnID) > a2aE2EERefMax {
		return fmt.Errorf("rpcclient: an A2A E2EE agent ref or txn is longer than %d bytes", a2aE2EERefMax)
	}
	return nil
}

func newA2AE2EEHandshake(initiator bool, prologue, key []byte, rng io.Reader) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{CipherSuite: a2aE2EESuite, Random: rng, Pattern: noise.HandshakeNN, Initiator: initiator, Prologue: prologue,
		PresharedKey: a2aE2EEPsk(key)}) // NNpsk0
}

// a2aE2EEState is one call's E2EE: the handshake, then a transport key per
// direction (send, recv).
type a2aE2EEState struct {
	mu      sync.Mutex
	waitCh  chan struct{}
	started bool
	ready   bool
	err     error // the handshake's failure
	broken  error // a frame that did not open: the call ended
	rng     io.Reader

	txnID          string
	caller, callee string         // the agent refs the prologue binds
	kr             A2AE2EEKeyring // this end's keys
	kid            string         // the call's key id
	keyFP          [sha256.Size]byte
	hs             *noise.HandshakeState
	send, recv     a2aCipher

	// Sessions (a2a_e2ee_session.go): established is the session a keyed
	// handshake left; a resumed call has session, its resume and
	// confirmed (closed once the callee took it), and keeps what it sent
	// until then (sent).
	established *a2aSession
	session     *a2aSession
	resume      []byte
	retry       []byte // caller: the retry its handshake after an unknown names; callee: the one an init named
	warm        bool   // a handshake with no call (WarmA2AE2EE): the caller's, or the callee's from message 1
	confirmed   chan struct{}
	sent        []a2aSentFrame
}

// a2aCipher is one direction's transport key: a Noise CipherState (a
// handshake's call) or a resumed call's key.
type a2aCipher interface {
	Encrypt(out, ad, plaintext []byte) ([]byte, error)
	Decrypt(out, ad, ciphertext []byte) ([]byte, error)
}

// newA2AE2EEState is the caller's state of a call from caller to callee.
func newA2AE2EEState(txnID, caller, callee string, kr A2AE2EEKeyring) *a2aE2EEState {
	return &a2aE2EEState{waitCh: make(chan struct{}), txnID: txnID, caller: caller, callee: callee, kr: kr, rng: rand.Reader}
}

// checkA2AE2EEKey is the per-frame check: the call's key id still holds.
func checkA2AE2EEKey(kr A2AE2EEKeyring, kid string) error {
	if !kr.Valid(kid) {
		return fmt.Errorf("rpcclient: A2A E2EE key %q was revoked or rotated; this call ends: %w", kid, errA2AE2EEPairing)
	}
	return nil
}

// revoked is the per-frame check asked now (RecheckA2AE2EE): the error an
// established call's next frame would get, or nil.
func (s *a2aE2EEState) revoked() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready {
		return nil // a handshake not done: its first frame is checked
	}
	return checkA2AE2EEKey(s.kr, s.kid)
}

func (s *a2aE2EEState) awaitingHandshake() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started && !s.ready && s.err == nil
}

func (s *a2aE2EEState) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready || s.err != nil {
		return
	}
	s.err = err
	if s.waitCh != nil {
		close(s.waitCh)
		s.waitCh = nil
	}
}

// initMessage starts the handshake: the key id is the one For gives for the
// callee (model RootInit/MachInit), message 1 is Noise's -> psk, e. The
// init payload is caller 0 callee 0 key id 0 message 1.
func (s *a2aE2EEState) initMessage() ([]byte, error) {
	kid, key, err := s.kr.For(s.callee)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: no A2A E2EE key to call %s: %v; %s: %w", s.callee, err, a2aE2EEPairingRemedy, errA2AE2EEPairing)
	}
	if err := a2aE2EEFieldsOK(s.txnID, s.caller, s.callee, kid); err != nil {
		return nil, err
	}
	hs, err := newA2AE2EEHandshake(true, a2aE2EEPrologue(s.txnID, a2aE2EERole(s.kr, kid, true), s.caller, s.callee, kid), key, s.rng)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: A2A E2EE handshake: %w", err)
	}
	var payload []byte
	switch {
	case s.warm:
		payload = []byte(a2aWarmMark) // model RootWarm: a relay cannot retag it as a call
	case s.resume == nil:
		payload = s.retry // a retry (restart); nil on a first handshake
	}
	msg1, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: A2A E2EE handshake: %w", err)
	}
	s.kid, s.hs, s.keyFP = kid, hs, sha256.Sum256(key)
	return append([]byte(s.caller+"\x00"+s.callee+"\x00"+kid+"\x00"), msg1...), nil
}

func (s *a2aE2EEState) ensureClientHandshake(ctx context.Context, transportDone <-chan struct{}, transportErr func() error, send func(messageType string, payload []byte) error) error {
	s.mu.Lock()
	if s.resume != nil && !s.started { // a resumed call: its resume, then its frames at once
		s.started = true
		resume := s.resume
		s.mu.Unlock()
		if err := send(a2aE2EEResumeMessageType, resume); err != nil {
			return fmt.Errorf("rpcclient: send A2A E2EE resume: %w", err)
		}
		return nil
	}
	if s.ready || s.err != nil {
		err := s.err
		s.mu.Unlock()
		return err
	}
	waitCh := s.waitCh
	if !s.started {
		s.started = true
		payload, err := s.initMessage()
		if err != nil {
			s.mu.Unlock()
			s.fail(err)
			return err
		}
		initType := a2aE2EEInitMessageType
		if s.warm {
			initType = a2aE2EEWarmMessageType
		}
		s.mu.Unlock()
		if err := send(initType, payload); err != nil {
			wrapped := fmt.Errorf("rpcclient: send A2A E2EE init: %w", err)
			s.fail(wrapped)
			return wrapped
		}
	} else {
		s.mu.Unlock()
	}

	select {
	case <-waitCh:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.err
	case <-ctx.Done():
		s.fail(ctx.Err())
		return ctx.Err()
	case <-transportDone:
		err := io.EOF
		if transportErr != nil {
			if transportFailure := transportErr(); transportFailure != nil {
				err = transportFailure
			}
		}
		s.fail(err)
		return err
	case <-time.After(a2aE2EEHandshakeTimeout):
		err := fmt.Errorf("rpcclient: A2A E2EE handshake timed out waiting for peer: %w", io.EOF)
		s.fail(err)
		return err
	}
}

// complete takes the peer's ack (Noise message 2, <- e, ee): the call's
// transport keys, or the handshake's refusal. keep (when not nil) gets the
// session the callee offered before a waiter wakes, so a call started once
// the handshake returns (a warm's next call) finds it and resumes.
func (s *a2aE2EEState) complete(ack []byte, keep func(*a2aSession)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready || s.err != nil {
		return s.err
	}
	if s.hs == nil {
		return fmt.Errorf("rpcclient: A2A E2EE handshake was not started")
	}
	offer, toPeer, fromPeer, err := s.hs.ReadMessage(nil, ack)
	if err == nil && (toPeer == nil || fromPeer == nil) {
		err = errors.New("the handshake did not complete")
	}
	if err != nil {
		s.err = fmt.Errorf("rpcclient: peer's A2A E2EE key failed pairing-key verification (a different key, or a relay in the middle; key id %q for %s): %v; %s: %w", s.kid, s.callee, err, a2aE2EEPairingRemedy, errA2AE2EEPairing)
	} else {
		s.send, s.recv, s.ready = toPeer, fromPeer, true
		if bytes.Equal(offer, a2aSessionOffer) {
			s.established = newA2ASession(toPeer, fromPeer, s.caller, s.callee, s.kid, s.keyFP, time.Now())
			if keep != nil {
				keep(s.established) // lock order: the state's mu, then the sessions'
			}
		}
	}
	s.hs = nil
	close(s.waitCh)
	s.waitCh = nil
	return s.err
}

// newServerA2AE2EEState answers an init for the agent own (model MachResp,
// RootResp): the init's callee must be own, its key id the one For gives
// for its caller, and message 1 must open under that key; the ack is Noise
// message 2.
func newServerA2AE2EEState(txnID, own string, init []byte, kr A2AE2EEKeyring, sessions bool, rng io.Reader) (*a2aE2EEState, []byte, error) {
	parts := bytes.SplitN(init, []byte{0}, 4)
	if len(parts) != 4 {
		return nil, nil, errors.New("rpcclient: malformed A2A E2EE init")
	}
	caller, callee, kid, msg1 := string(parts[0]), string(parts[1]), string(parts[2]), parts[3]
	if err := a2aE2EEFieldsOK(txnID, caller, callee, kid); err != nil {
		return nil, nil, err
	}
	// own is the ref the relay registered this agent under (Agent.Ref); any
	// other callee is a call for another agent. The relay states own, so
	// this check only names a misroute: the key below binds the call.
	if callee != own {
		return nil, nil, fmt.Errorf("rpcclient: an A2A E2EE call for %s reached %s (the relay routed it here): %w", callee, own, errA2AE2EEPairing)
	}
	if n := len(msg1) - a2aE2EEKeyedMsg1Len; n != 0 && n != len(a2aWarmMark) && n != a2aRetryLen {
		return nil, nil, errors.New("rpcclient: malformed A2A E2EE init")
	}
	key, err := a2aE2EEAnswerKey(kr, caller, kid)
	if err != nil {
		return nil, nil, err
	}
	var offer []byte // no session offered: a callee with no replay record keeps none
	if sessions {
		offer = a2aSessionOffer
	}
	hs, err := newA2AE2EEHandshake(false, a2aE2EEPrologue(txnID, a2aE2EERole(kr, kid, false), caller, callee, kid), key, rng)
	if err != nil {
		return nil, nil, fmt.Errorf("rpcclient: A2A E2EE handshake: %w", err)
	}
	payload, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil {
		return nil, nil, fmt.Errorf("rpcclient: peer's A2A E2EE key failed pairing-key verification (a different key, or a relay in the middle); %s: %w", a2aE2EEPairingRemedy, errA2AE2EEPairing)
	}
	ack, fromPeer, toPeer, err := hs.WriteMessage(nil, offer)
	if err != nil {
		return nil, nil, fmt.Errorf("rpcclient: A2A E2EE handshake: %w", err)
	}
	s := &a2aE2EEState{started: true, ready: true, txnID: txnID, caller: caller, callee: callee, kr: kr, kid: kid, send: toPeer, recv: fromPeer}
	switch string(payload) {
	case "":
	case a2aWarmMark:
		s.warm = true
	default:
		s.retry = payload
	}
	if sessions {
		s.established = newA2ASession(fromPeer, toPeer, caller, callee, kid, sha256.Sum256(key), time.Now())
	}
	return s, ack, nil
}

// a2aE2EEAnswerKey is the key a callee answers caller's init under key id
// kid with: the one its keyring gives for caller, under that id only.
func a2aE2EEAnswerKey(kr A2AE2EEKeyring, caller, kid string) ([]byte, error) {
	want, k, err := kr.For(caller)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: peer's A2A E2EE key id %q refused for caller %s: %v; %s: %w", kid, caller, err, a2aE2EEPairingRemedy, errA2AE2EEPairing)
	}
	if want != kid {
		return nil, fmt.Errorf("rpcclient: caller %s named A2A E2EE key id %q, this end answers it only under %q; %s: %w", caller, kid, want, a2aE2EEPairingRemedy, errA2AE2EEPairing)
	}
	return k, nil
}

// seal is one frame of type t (model: aenc(split, n, ad(t), (type, body))).
// Frames are sealed in the order they are sent: each end's frames of a
// call have one sender at a time.
func (s *a2aE2EEState) seal(t byte, body []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil { // a refused resume's handshake failed (rehandshake)
		return nil, s.err
	}
	if !s.ready || s.send == nil {
		return nil, fmt.Errorf("rpcclient: A2A E2EE is not established")
	}
	if err := checkA2AE2EEKey(s.kr, s.kid); err != nil {
		return nil, err
	}
	ct, err := s.send.Encrypt(nil, []byte(s.txnID), append([]byte{t}, body...))
	if err == nil {
		s.keep(t, body)
	}
	return ct, err
}

// open is the next frame from the peer: one that does not open (replayed,
// reordered, after a dropped one, reflected, forged) ends the call.
func (s *a2aE2EEState) open(ciphertext []byte) (byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready || s.recv == nil {
		return 0, nil, fmt.Errorf("rpcclient: A2A E2EE is not established")
	}
	if s.broken != nil {
		return 0, nil, s.broken
	}
	if err := checkA2AE2EEKey(s.kr, s.kid); err != nil {
		return 0, nil, err
	}
	pt, err := s.recv.Decrypt(nil, []byte(s.txnID), ciphertext)
	if err != nil || len(pt) == 0 {
		s.broken = errors.New("rpcclient: an A2A E2EE frame did not open (replayed, reordered, after a dropped frame, reflected or forged by the relay); the call ends")
		return 0, nil, s.broken
	}
	return pt[0], pt[1:], nil
}

// openData is the body of the next data frame.
func (s *a2aE2EEState) openData(ciphertext []byte) ([]byte, error) {
	t, body, err := s.open(ciphertext)
	if err == nil && t != a2aFrameData {
		err = fmt.Errorf("rpcclient: an A2A E2EE frame of type %d where data was due", t)
	}
	return body, err
}

func a2aErrorBody(code codes.Code, detail string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(code)), detail...)
}

func parseA2AErrorBody(body []byte) (codes.Code, string, bool) {
	if len(body) < 4 {
		return 0, "", false
	}
	return codes.Code(binary.BigEndian.Uint32(body)), string(body[4:]), true
}

// errA2AE2EERelayEnded is an end of stream or an error an E2EE call got in
// the clear: the relay's (or unauthenticated), never the peer's.
func errA2AE2EERelayEnded(code codes.Code, detail string) error {
	if code == codes.OK {
		code = codes.Unavailable
	}
	msg := "rpcclient: the relay ended the call (not end-to-end authenticated by the peer)"
	if detail != "" {
		msg += ": " + detail
	}
	return status.Error(code, msg)
}

func withA2AE2EEHeaders(md MD) MD {
	out := make(MD, len(md)+2)
	maps.Copy(out, md)
	out[a2aE2EEHeaderKey] = "true"
	out[a2aE2EECipherKey] = a2aE2EECipherName
	return out
}
