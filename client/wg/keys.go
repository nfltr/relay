// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeyPair generates a new Curve25519 key pair for WireGuard.
// Returns (privateKey, publicKey) as base64-encoded strings.
func GenerateKeyPair() (string, string, error) {
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", fmt.Errorf("wg: generate private key: %w", err)
	}
	// Clamp per Curve25519 conventions (same as WireGuard).
	privKey[0] &= 248
	privKey[31] = (privKey[31] & 127) | 64

	pubKey, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("wg: derive public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(privKey[:]),
		base64.StdEncoding.EncodeToString(pubKey), nil
}

// PublicKeyFromPrivate derives the Curve25519 public key from a base64-encoded private key.
func PublicKeyFromPrivate(privKeyB64 string) (string, error) {
	privKey, err := decodeBase64Key(privKeyB64)
	if err != nil {
		return "", err
	}
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("wg: derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pubKey), nil
}

// decodeBase64Key decodes a base64-encoded WireGuard key (32 bytes).
func decodeBase64Key(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("wg: decode key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("wg: key must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

// hexKey converts a base64-encoded WireGuard key to the lowercase hex
// encoding expected by the wireguard-go IPC protocol.
func hexKey(b64 string) (string, error) {
	raw, err := decodeBase64Key(b64)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", raw), nil
}

// presharedKeyContext separates the WireGuard preshared key from other keys
// derived from the same pairing file (the A2A E2EE pairing key).
const presharedKeyContext = "nfltr-wg-psk-v1"

// PresharedKeyFromFile derives a WireGuard preshared key (base64) from a
// pairing key file (--e2ee-key-file): SHA-256(context ‖ secret). The client
// and the exit set it on each other, so a relay that swaps in its own public
// key cannot complete a handshake with either. The secret must be random: a
// relay sees handshakes and could test guesses of a short one offline.
func PresharedKeyFromFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("wg: read pairing key file: %w", err)
	}
	secret := bytes.TrimSpace(raw)
	if len(secret) < 32 {
		return "", fmt.Errorf("wg: pairing key file %s holds %d bytes; want at least 32 bytes of random secret (e.g. openssl rand -hex 32)", path, len(secret))
	}
	sum := sha256.Sum256(append([]byte(presharedKeyContext), secret...))
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}
