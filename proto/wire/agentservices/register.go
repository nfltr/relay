// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agentservices

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
)

// A capability address's registration (nfltr
// docs/decisions/nf1-risks-2026-11-14.md, relay spec/proverif
// cap_address.pv query 25): what a relay needs to take an agent's
// declaration of a rid only from the holder of the address's server key.
// The relay links this; the client's capaddr mints and signs with it.

// ErrRegister is CheckRegistration's refusal.
var ErrRegister = errors.New("nf1: registration proof refused (rid not bound to this key, or not signed by it over this relay and rid)")

// MaxRelayHost bounds a capability address's relay host R (one length
// byte in the address).
const MaxRelayHost = 255

const (
	tagRID      = "nf1-rid"
	tagRegister = "nf1-reg"
)

// RIDOf is SHA-256("nf1-rid" || n || spki)[:16]: the rid
// bound to the server's key (spki, its DER SubjectPublicKeyInfo), so
// another key cannot claim it without a second preimage.
func RIDOf(n [RIDSize]byte, spki []byte) [RIDSize]byte {
	h := sha256.New()
	h.Write([]byte(tagRID))
	h.Write(n[:])
	h.Write(spki)
	return [RIDSize]byte(h.Sum(nil)[:RIDSize])
}

// RegisterMessage is what a registration proof signs: "nf1-reg" | len(R)
// (2 bytes) | R | rid. relay is at most MaxRelayHost bytes.
func RegisterMessage(relay string, rid [RIDSize]byte) []byte {
	b := make([]byte, 0, len(tagRegister)+2+len(relay)+RIDSize)
	b = append(b, tagRegister...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(relay))) // #nosec G115 -- callers bound relay to MaxRelayHost
	b = append(b, relay...)
	return append(b, rid[:]...)
}

// CheckRegistration is R's check of a declaration of rid at relay (R's own
// host, as its addresses name it) (BIND:cap.register): the proof is n |
// len(spki) (2 bytes) | spki | sig, and it holds when rid = RIDOf(n, spki)
// and sig is spki's Ed25519 signature over RegisterMessage(relay, rid).
// The rendezvous record, which every opener gets, is under another tag and
// never passes.
func CheckRegistration(relay string, rid [RIDSize]byte, proof []byte) error {
	if relay == "" || len(relay) > MaxRelayHost || len(proof) < RIDSize+2 {
		return ErrRegister
	}
	n := [RIDSize]byte(proof[:RIDSize])
	l := int(binary.BigEndian.Uint16(proof[RIDSize:]))
	rest := proof[RIDSize+2:]
	if len(rest) != l+ed25519.SignatureSize {
		return ErrRegister
	}
	spki, sig := rest[:l], rest[l:]
	k, err := x509.ParsePKIXPublicKey(spki)
	pub, ok := k.(ed25519.PublicKey)
	if err != nil || !ok || RIDOf(n, spki) != rid || !ed25519.Verify(pub, RegisterMessage(relay, rid), sig) {
		return ErrRegister
	}
	return nil
}
