// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

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

// presharedKeyLabel separates the WireGuard preshared key from the other
// keys of the same A2A key.
const presharedKeyLabel = "nfltr-wg-psk-v2"

// PresharedKey is the WireGuard preshared key (base64) of the exit named
// exit: HMAC-SHA256(key, label 0 service 0 keyID), key the exit's A2A key
// (the owner's root key, keyID ""; or the machine key keyID names). The
// client and the exit set it on each other, so a relay that swaps in its
// own public key cannot complete a handshake with either, and one that
// reroutes a client to another exit holding the same key cannot either:
// each end binds its own name for the exit, the client the one it named,
// the exit its own (spec/proverif wg_exit.pv, query 4).
func PresharedKey(key []byte, exit, keyID string) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("wg: an A2A key of %d bytes; want at least 32", len(key))
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(presharedKeyLabel + "\x00" + ExitService(exit) + "\x00" + keyID))
	return base64.StdEncoding.EncodeToString(m.Sum(nil)), nil
}

// ExitService is an exit's service name: the part after an agent ref's
// machine id ("m-" and 26 base32 characters, then "-"), the part after a
// machine name and ".", or the name itself.
// A client may name an exit either way; the exit binds its own the same way.
func ExitService(name string) string {
	const machineIDLen = 28 // relay-core identity.MachineIDLen
	if len(name) > machineIDLen+1 && strings.HasPrefix(name, "m-") && name[machineIDLen] == '-' {
		return name[machineIDLen+1:]
	}
	if _, svc, dotted := strings.Cut(name, "."); dotted {
		return svc // "<machine name>.<service>" (services hold no ".")
	}
	return name
}
