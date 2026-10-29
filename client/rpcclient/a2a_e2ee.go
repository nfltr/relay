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
	txnID   string // initiator: the transaction the handshake tags bind to
	pairing []byte // initiator: pairing key the peer must prove, or nil
	recvKey []byte // the peer's direction when it differs from key (0-RTT)

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

func newA2AE2EEState(txnID string, pairing []byte) *a2aE2EEState {
	return &a2aE2EEState{waitCh: make(chan struct{}), txnID: txnID, pairing: pairing}
}

// errA2AE2EEPairing marks a handshake refused because a peer did not prove
// the pairing key (or proved one this end does not use).
var errA2AE2EEPairing = errors.New("A2A E2EE pairing key")

const (
	a2aE2EEPubLen            = 32 // X25519 public key
	a2aE2EEPairingTagLen     = sha256.Size
	a2aE2EEPairingMinSecret  = 32
	a2aE2EEPairingRemedy     = "set the same --e2ee-key-file / NFLTR_A2A_E2EE_KEY_FILE on both ends"
	a2aE2EEPairingKeyContext = "nfltr-a2a-e2ee-pairing-v1"
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
// with a pairing key, verifies the tag the peer computed over wantTag's
// inputs. Unkeyed ends exchange a bare public key.
func splitA2AE2EEHandshake(payload, pairing []byte, wantTag func(pub []byte) []byte) ([]byte, error) {
	switch {
	case pairing == nil && len(payload) == a2aE2EEPubLen+a2aE2EEPairingTagLen:
		return nil, fmt.Errorf("rpcclient: peer authenticates A2A E2EE with a pairing key this end does not have; %s: %w", a2aE2EEPairingRemedy, errA2AE2EEPairing)
	case pairing == nil:
		return payload, nil
	case len(payload) != a2aE2EEPubLen+a2aE2EEPairingTagLen:
		return nil, fmt.Errorf("rpcclient: peer did not authenticate its A2A E2EE key with the pairing key (no pairing key there, or an older nfltr); %s: %w", a2aE2EEPairingRemedy, errA2AE2EEPairing)
	}
	pub, tag := payload[:a2aE2EEPubLen], payload[a2aE2EEPubLen:]
	if !hmac.Equal(tag, wantTag(pub)) {
		return nil, fmt.Errorf("rpcclient: peer's A2A E2EE key failed pairing-key verification (a different key, or a relay in the middle); %s: %w", a2aE2EEPairingRemedy, errA2AE2EEPairing)
	}
	return pub, nil
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
	if s.pairing != nil {
		pub = append(pub, a2aE2EEPairingTag(s.pairing, "init", s.txnID, pub)...)
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
	peerPub, err := splitA2AE2EEHandshake(peerPub, s.pairing, func(pub []byte) []byte {
		return a2aE2EEPairingTag(s.pairing, "ack", s.txnID, ownPub, pub)
	})
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
	key := deriveA2AE2EESessionKey(s.pairing, shared, ownPub, peerPub)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.key = key
	s.ready = true
	if waitCh != nil {
		close(waitCh)
		s.waitCh = nil
	}
	return nil
}

// newServerA2AE2EEState answers an init: with a pairing key it first
// verifies the initiator's tag, and its ack carries a tag over both keys.
func newServerA2AE2EEState(txnID string, initPayload, pairing []byte) (*a2aE2EEState, []byte, error) {
	peerPub, err := splitA2AE2EEHandshake(initPayload, pairing, func(pub []byte) []byte {
		return a2aE2EEPairingTag(pairing, "init", txnID, pub)
	})
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
	ack := append([]byte(nil), ownPub...)
	if pairing != nil {
		ack = append(ack, a2aE2EEPairingTag(pairing, "ack", txnID, peerPub, ownPub)...)
	}
	return state, ack, nil
}

func (s *a2aE2EEState) encrypt(txnID string, plaintext []byte) ([]byte, error) {
	key := s.readyKey()
	if len(key) == 0 {
		return nil, fmt.Errorf("rpcclient: A2A E2EE is not established")
	}
	return a2aE2EESeal(key, rand.Reader, txnID, plaintext)
}

func (s *a2aE2EEState) decrypt(txnID string, ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	key := s.recvKey
	if key == nil {
		key = s.key
	}
	ready := s.ready
	s.mu.Unlock()
	if !ready || len(key) == 0 {
		return nil, fmt.Errorf("rpcclient: A2A E2EE is not established")
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
