// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package appenrol is an app's side of enrolling a device for a person
// into an organisation (nfltr docs/decisions/app-device-identity-2026-11-16.md;
// models spec/proverif/app_enrol.pv and spec/appenrol/AppEnrol.tla): the
// OpenID Connect nonce that commits the person's ID token to the device's
// two keys, its relay key and its organisation key (the key commitment of
// OpenPubkey). The relay's accounts service and the organisation's issuer
// each take the token only with the keys its nonce names, so the relay,
// which carries the token, cannot attach a key of its own to it.
package appenrol

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

const nonceLabel = "nfltr-app-enrol-v1"

// Nonce is base64url (no padding) of SHA-256(label || len || SPKI(relayKey)
// || len || SPKI(orgKey)), each length two bytes big-endian (BIND:app.nonce).
func Nonce(relayKey, orgKey crypto.PublicKey) (string, error) {
	h := sha256.New()
	h.Write([]byte(nonceLabel))
	for _, k := range []crypto.PublicKey{relayKey, orgKey} {
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return "", fmt.Errorf("appenrol: %w", err)
		}
		h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(der)))) // #nosec G115 -- an SPKI is far below 64 KiB
		h.Write(der)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// ErrNonce: the token's nonce names other keys.
var ErrNonce = errors.New("appenrol: the sign-in's nonce does not name these keys")

// CheckNonce is what a verifier of the sign-in checks: nonce (the ID
// token's) names exactly relayKey and orgKey, in that order.
func CheckNonce(nonce string, relayKey, orgKey crypto.PublicKey) error {
	want, err := Nonce(relayKey, orgKey)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(want)) != 1 {
		return ErrNonce
	}
	return nil
}
