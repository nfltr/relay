// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const (
	a2aE2EEInitMessageType = "a2a-e2ee-init"
	a2aE2EEAckMessageType  = "a2a-e2ee-ack"

	// a2aE2EEHandshakeTimeout caps how long the initiator waits for the peer
	// to complete the key exchange. If the peer disconnects without responding
	// the caller can retry rather than waiting for the full task timeout.
	a2aE2EEHandshakeTimeout = 30 * time.Second

	a2aE2EEHeaderKey  = "x-a2a-e2ee"
	a2aE2EECipherKey  = "x-a2a-e2ee-cipher"
	a2aE2EECipherName = "x25519-aes-256-gcm"
)

type a2aE2EEState struct {
	mu      sync.Mutex
	waitCh  chan struct{}
	started bool
	ready   bool
	key     []byte
	priv    *ecdh.PrivateKey
	err     error
	txnID   string         // initiator: the transaction the handshake tags bind to
	kr      A2AE2EEKeyring // this end's keys, or nil (unkeyed)
	kid     string         // the call's key id: Own's until the peer's ack (or label) names it
	pk      []byte         // the key kid names: the call's tag and session key input
	recvKey []byte         // the peer's direction when it differs from key (0-RTT)

	// 0-RTT initiator (a2a_e2ee_0rtt.go): the peer's advertised static key
	// and, with a pairing key, the name its label proves; while the first
	// flight awaits its ack, the handshake, its ephemeral key, when it was
	// sent and the request to re-send if the peer refuses it.
	peerStatic []byte
	peerName   string
	hs         *noise.HandshakeState
	eph        []byte
	sentAt     time.Time
	early      []byte
	inner      *a2aE2EEState // the interactive handshake run after a refusal
}

func newA2AE2EEState(txnID string, kr A2AE2EEKeyring) *a2aE2EEState {
	s := &a2aE2EEState{waitCh: make(chan struct{}), txnID: txnID, kr: kr}
	if kr != nil {
		s.kid, s.pk = kr.Own()
	}
	return s
}

// A2AE2EEKeyring is one end's A2A E2EE pairing keys
// (WithA2AE2EEKeyring). A key id names a key: "" is the root pairing key
// (LoadA2AE2EEPairingKey), which every root holder has; any other id is a
// machine key the caller manages (nfltr derives one per machine from the
// root key, docs/decisions/a2a-per-machine-keys-2026-11-07.md).
//
// Wire: a keyed handshake payload is pub ‖ tag ‖ key id (the id in the
// clear, at most a2aE2EEKeyIDMax bytes; none is ""), the tag
// HMAC-SHA256 under the key the id names. The initiator's init carries
// Own(); the responder answers under the init's id (a machine end that
// gets a root holder's "" answers under its own id and key: only a holder
// of that key derives the session key) and its ack names the id it used,
// which the initiator resolves with Peer. The static label carries Own()'s
// id as "~" + base64url(id) after its tag; a 0-RTT first flight and its
// retry are under the label's key. A refused id refuses the handshake
// before any key is used.
type A2AE2EEKeyring interface {
	// Own is this end's key id and key: the tags it starts with.
	Own() (id string, key []byte)
	// Peer is the key a peer's key id names; an error refuses the handshake.
	Peer(id string) ([]byte, error)
	// Valid reports whether an established call's key id still holds. It is
	// asked before each later frame of the call is sealed or opened, so a
	// revoke ends calls in flight at their next frame.
	Valid(id string) bool
}

// a2aE2EEPairingKey is the keyring of a root pairing key alone: id "" only.
type a2aE2EEPairingKey []byte

func (k a2aE2EEPairingKey) Own() (string, []byte) { return "", k }

func (k a2aE2EEPairingKey) Peer(id string) ([]byte, error) {
	if id != "" {
		return nil, fmt.Errorf("this end holds the pairing key only, no machine keys")
	}
	return k, nil
}

func (k a2aE2EEPairingKey) Valid(id string) bool { return id == "" }

// errA2AE2EEPairing marks a handshake refused because a peer did not prove
// the pairing key (or proved one this end does not use).
var errA2AE2EEPairing = errors.New("A2A E2EE pairing key")

const (
	a2aE2EEPubLen            = 32 // X25519 public key
	a2aE2EEPairingTagLen     = sha256.Size
	a2aE2EEPairingMinSecret  = 32
	a2aE2EEPairingRemedy     = "set the same --e2ee-key-file / NFLTR_A2A_E2EE_KEY_FILE on both ends"
	a2aE2EEPairingKeyContext = "nfltr-a2a-e2ee-pairing-v1"
	a2aE2EEKeyIDMax          = 128
)

// LoadA2AE2EEPairingKey reads a pairing key file and derives the 32-byte key
// K = SHA-256(context ‖ secret). The secret must be random: tags observed by
// the relay would let it test guesses of a short passphrase offline. nfltr
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

// a2aE2EEPairingTag is HMAC-SHA256(K, label ‖ 0 ‖ txn ‖ 0 ‖ keys...).
func a2aE2EEPairingTag(key []byte, label, txnID string, keys ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(label))
	m.Write([]byte{0})
	m.Write([]byte(txnID))
	m.Write([]byte{0})
	for _, k := range keys {
		m.Write(k)
	}
	return m.Sum(nil)
}

// splitA2AE2EEHandshake splits a handshake payload into the public key and,
// with a keyring, the tag and the key id beside it. Unkeyed ends exchange a
// bare public key.
func splitA2AE2EEHandshake(payload []byte, kr A2AE2EEKeyring) (pub, tag []byte, kid string, err error) {
	keyed := len(payload) >= a2aE2EEPubLen+a2aE2EEPairingTagLen
	switch {
	case kr == nil && keyed:
		return nil, nil, "", fmt.Errorf("rpcclient: peer authenticates A2A E2EE with a pairing key this end does not have; %s: %w", a2aE2EEPairingRemedy, errA2AE2EEPairing)
	case kr == nil:
		return payload, nil, "", nil
	case !keyed:
		return nil, nil, "", fmt.Errorf("rpcclient: peer did not authenticate its A2A E2EE key with the pairing key (no pairing key there, or an older nfltr); %s: %w", a2aE2EEPairingRemedy, errA2AE2EEPairing)
	case len(payload) > a2aE2EEPubLen+a2aE2EEPairingTagLen+a2aE2EEKeyIDMax:
		return nil, nil, "", fmt.Errorf("rpcclient: peer's A2A E2EE key id is longer than %d bytes: %w", a2aE2EEKeyIDMax, errA2AE2EEPairing)
	}
	return payload[:a2aE2EEPubLen], payload[a2aE2EEPubLen : a2aE2EEPubLen+a2aE2EEPairingTagLen], string(payload[a2aE2EEPubLen+a2aE2EEPairingTagLen:]), nil
}

// verifyA2AE2EETag resolves kid with the keyring and checks tag under its
// key (want computes the expected tag for a key): the key, or a refusal.
func verifyA2AE2EETag(kr A2AE2EEKeyring, kid string, tag []byte, want func(key []byte) []byte) ([]byte, error) {
	key, err := kr.Peer(kid)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: peer's A2A E2EE key id %q refused: %v; %s: %w", kid, err, a2aE2EEPairingRemedy, errA2AE2EEPairing)
	}
	if !hmac.Equal(tag, want(key)) {
		return nil, fmt.Errorf("rpcclient: peer's A2A E2EE key failed pairing-key verification (a different key, or a relay in the middle); %s: %w", a2aE2EEPairingRemedy, errA2AE2EEPairing)
	}
	return key, nil
}

// checkA2AE2EEKey is the per-frame check: the call's key id still holds.
func checkA2AE2EEKey(kr A2AE2EEKeyring, kid string) error {
	if kr != nil && !kr.Valid(kid) {
		return fmt.Errorf("rpcclient: A2A E2EE key %q was revoked or rotated; this call ends: %w", kid, errA2AE2EEPairing)
	}
	return nil
}

// deriveA2AE2EESessionKey binds the session key to the pairing key and both
// public keys when a pairing key is in use; unkeyed ends keep the v1 KDF.
func deriveA2AE2EESessionKey(pairing, shared, initiatorPub, responderPub []byte) []byte {
	if pairing == nil {
		return deriveA2AE2EEKey(shared)
	}
	return a2aE2EEPairingTag(pairing, "session", "", shared, initiatorPub, responderPub)
}

func newEstablishedA2AE2EEState(key []byte) *a2aE2EEState {
	waitCh := make(chan struct{})
	close(waitCh)
	return &a2aE2EEState{
		waitCh:  waitCh,
		started: true,
		ready:   true,
		key:     append([]byte(nil), key...),
	}
}

func (s *a2aE2EEState) awaitingHandshake() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started && !s.ready && s.err == nil
}

func (s *a2aE2EEState) readyKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready {
		return nil
	}
	return append([]byte(nil), s.key...)
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

func (s *a2aE2EEState) ensureClientHandshake(ctx context.Context, transportDone <-chan struct{}, transportErr func() error, sendInit func(pub []byte) error) error {
	s.mu.Lock()
	if s.ready {
		s.mu.Unlock()
		return nil
	}
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return err
	}
	if s.started {
		waitCh := s.waitCh
		s.mu.Unlock()
		select {
		case <-waitCh:
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.err
		case <-ctx.Done():
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

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		s.err = fmt.Errorf("rpcclient: generate A2A E2EE keypair: %w", err)
		close(s.waitCh)
		waitErr := s.err
		s.waitCh = nil
		s.mu.Unlock()
		return waitErr
	}

	s.started = true
	s.priv = priv
	pub := append([]byte(nil), priv.PublicKey().Bytes()...)
	if s.kr != nil {
		pub = append(append(pub, a2aE2EEPairingTag(s.pk, "init", s.txnID, pub)...), s.kid...)
	}
	waitCh := s.waitCh
	s.mu.Unlock()

	if err := sendInit(pub); err != nil {
		wrapped := fmt.Errorf("rpcclient: send A2A E2EE init: %w", err)
		s.fail(wrapped)
		return wrapped
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

func (s *a2aE2EEState) complete(peerPub []byte) error {
	s.mu.Lock()
	if inner := s.inner; inner != nil {
		s.mu.Unlock()
		return inner.complete(peerPub)
	}
	if hs := s.hs; hs != nil && !s.ready && s.err == nil {
		s.mu.Unlock()
		return s.completeZeroRTT(hs, peerPub)
	}
	if s.ready {
		s.mu.Unlock()
		return nil
	}
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return err
	}
	priv := s.priv
	waitCh := s.waitCh
	s.mu.Unlock()

	if priv == nil {
		return fmt.Errorf("rpcclient: A2A E2EE handshake was not started")
	}
	ownPub := priv.PublicKey().Bytes()
	peerPub, tag, kid, err := splitA2AE2EEHandshake(peerPub, s.kr)
	var pk []byte
	if err == nil && s.kr != nil {
		pk, err = verifyA2AE2EETag(s.kr, kid, tag, func(key []byte) []byte {
			return a2aE2EEPairingTag(key, "ack", s.txnID, ownPub, peerPub)
		})
	}
	if err != nil {
		s.fail(err)
		return err
	}

	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		wrapped := fmt.Errorf("rpcclient: parse A2A E2EE peer key: %w", err)
		s.fail(wrapped)
		return wrapped
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		wrapped := fmt.Errorf("rpcclient: derive A2A E2EE shared secret: %w", err)
		s.fail(wrapped)
		return wrapped
	}
	key := deriveA2AE2EESessionKey(pk, shared, ownPub, peerPub)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.key, s.kid, s.pk = key, kid, pk
	s.ready = true
	if waitCh != nil {
		close(waitCh)
		s.waitCh = nil
	}
	return nil
}

// newServerA2AE2EEState answers an init: with a keyring it first verifies
// the initiator's tag under the key its id names, and its ack carries a tag
// over both keys and the id it used.
func newServerA2AE2EEState(txnID string, initPayload []byte, kr A2AE2EEKeyring) (*a2aE2EEState, []byte, error) {
	peerPub, tag, kid, err := splitA2AE2EEHandshake(initPayload, kr)
	var pairing []byte
	if err == nil && kr != nil {
		if ownID, ownKey := kr.Own(); kid == "" && ownID != "" {
			// A root holder's init to a machine: the machine cannot check a
			// root-key tag, so it answers under its own key. Only a holder of
			// that key verifies the ack and derives the session key, so
			// nothing anyone else sends on this call decrypts.
			kid, pairing = ownID, ownKey
		} else {
			pairing, err = verifyA2AE2EETag(kr, kid, tag, func(key []byte) []byte {
				return a2aE2EEPairingTag(key, "init", txnID, peerPub)
			})
		}
	}
	if err != nil {
		return nil, nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("rpcclient: generate A2A E2EE responder keypair: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, nil, fmt.Errorf("rpcclient: parse A2A E2EE initiator key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("rpcclient: derive A2A E2EE responder shared secret: %w", err)
	}
	ownPub := priv.PublicKey().Bytes()
	state := newEstablishedA2AE2EEState(deriveA2AE2EESessionKey(pairing, shared, peerPub, ownPub))
	state.kr, state.kid, state.pk = kr, kid, pairing
	ack := append([]byte(nil), ownPub...)
	if kr != nil {
		ack = append(append(ack, a2aE2EEPairingTag(pairing, "ack", txnID, peerPub, ownPub)...), kid...)
	}
	return state, ack, nil
}

func (s *a2aE2EEState) encrypt(txnID string, plaintext []byte) ([]byte, error) {
	key := s.readyKey()
	if len(key) == 0 {
		return nil, fmt.Errorf("rpcclient: A2A E2EE is not established")
	}
	s.mu.Lock()
	kr, kid := s.kr, s.kid
	s.mu.Unlock()
	if err := checkA2AE2EEKey(kr, kid); err != nil {
		return nil, err
	}
	return a2aE2EESeal(key, rand.Reader, txnID, plaintext)
}

func (s *a2aE2EEState) decrypt(txnID string, ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	key := s.recvKey
	if key == nil {
		key = s.key
	}
	ready, kr, kid := s.ready, s.kr, s.kid
	s.mu.Unlock()
	if !ready || len(key) == 0 {
		return nil, fmt.Errorf("rpcclient: A2A E2EE is not established")
	}
	if err := checkA2AE2EEKey(kr, kid); err != nil {
		return nil, err
	}
	return a2aE2EEOpen(key, txnID, ciphertext)
}

// a2aE2EESeal is AES-256-GCM with a random nonce, prefixed, and the txn id
// in the AAD.
func a2aE2EESeal(key []byte, rng io.Reader, txnID string, plaintext []byte) ([]byte, error) {
	gcm, err := a2aE2EEGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rng, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, a2aE2EEAAD(txnID)), nil
}

func a2aE2EEOpen(key []byte, txnID string, ciphertext []byte) ([]byte, error) {
	gcm, err := a2aE2EEGCM(key)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("rpcclient: ciphertext too short")
	}
	nonce, payload := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, payload, a2aE2EEAAD(txnID))
}

func a2aE2EEGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func deriveA2AE2EEKey(shared []byte) []byte {
	sum := sha256.Sum256(append([]byte("nfltr-a2a-e2ee-v1"), shared...))
	key := make([]byte, len(sum))
	copy(key, sum[:])
	return key
}

func a2aE2EEAAD(txnID string) []byte {
	return []byte("nfltr-a2a-e2ee-v1:" + txnID)
}

func withA2AE2EEHeaders(md MD) MD {
	out := make(MD, len(md)+2)
	maps.Copy(out, md)
	out[a2aE2EEHeaderKey] = "true"
	out[a2aE2EECipherKey] = a2aE2EECipherName
	return out
}
