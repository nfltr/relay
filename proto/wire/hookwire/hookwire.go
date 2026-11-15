// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package hookwire is the sealed webhook row of nfltr.mailbox.v1
// (WebhookRecipient): the mailbox service seals each accepted body to the
// webhook's recipient key at ingress, so its store holds no body; the
// recipient opens it. HPKE base mode (RFC 9180, Go crypto/hpke): DHKEM(P-256),
// HKDF-SHA256, AES-256-GCM, single shot.
//
//	row       = len(key_id) (1 byte) || key_id || enc || ciphertext
//	plaintext = len(content_type) (2 bytes, big endian) || content_type ||
//	            len(body) (4 bytes, big endian) || body || zeros to a PadBucket multiple
//	info      = "nfltr-hook-v1" 0x00 owner 0x00 mailbox 0x00 webhook id 0x00 key id
package hookwire

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
)

// PadBucket is the plaintext padding granularity: a row's size says the
// body's only to the bucket.
const PadBucket = 1024

// MaxKeyID bounds a recipient key id.
const MaxKeyID = 64

// Binding is what a row is sealed for; the opener names the same.
type Binding struct {
	Owner, Mailbox, WebhookID, KeyID string
}

func (b Binding) info() []byte {
	return []byte("nfltr-hook-v1\x00" + b.Owner + "\x00" + b.Mailbox + "\x00" + b.WebhookID + "\x00" + b.KeyID)
}

func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

// ErrMalformed is a row that is not one of this package's.
var ErrMalformed = errors.New("hookwire: malformed sealed row")

// ValidKeyID reports whether id can name a recipient: 1-MaxKeyID bytes of
// printable ASCII.
func ValidKeyID(id string) bool {
	if id == "" || len(id) > MaxKeyID {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return true
}

// ParseRecipient is the uncompressed P-256 point of a recipient.
func ParseRecipient(raw []byte) (*ecdh.PublicKey, error) {
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("hookwire: recipient key: %w", err)
	}
	return pub, nil
}

// Seal seals contentType and body to pub for b (b.KeyID names pub).
func Seal(pub *ecdh.PublicKey, b Binding, contentType string, body []byte) ([]byte, error) {
	if !ValidKeyID(b.KeyID) {
		return nil, errors.New("hookwire: invalid key id")
	}
	if len(contentType) > 0xffff || uint64(len(body)) > 0xffffffff {
		return nil, errors.New("hookwire: too large")
	}
	n := 2 + len(contentType) + 4 + len(body)
	plain := make([]byte, (n/PadBucket+1)*PadBucket)
	binary.BigEndian.PutUint16(plain, uint16(len(contentType))) // #nosec G115 -- checked above
	copy(plain[2:], contentType)
	binary.BigEndian.PutUint32(plain[2+len(contentType):], uint32(len(body))) // #nosec G115 -- checked above
	copy(plain[6+len(contentType):], body)
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, err
	}
	kdf, aead := suite()
	sealed, err := hpke.Seal(pk, kdf, aead, b.info(), plain)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{byte(len(b.KeyID))}, b.KeyID...), sealed...), nil // #nosec G115 -- ValidKeyID bounds the id to MaxKeyID bytes
}

// KeyID is the recipient key id a row names (which private key opens it).
func KeyID(row []byte) (string, error) {
	if len(row) < 1 || len(row) < 1+int(row[0]) || !ValidKeyID(string(row[1:1+int(row[0])])) {
		return "", ErrMalformed
	}
	return string(row[1 : 1+int(row[0])]), nil
}

// Open opens a row sealed for b with priv; b.KeyID must be the row's.
func Open(priv *ecdh.PrivateKey, b Binding, row []byte) (contentType string, body []byte, err error) {
	id, err := KeyID(row)
	if err != nil {
		return "", nil, err
	}
	if id != b.KeyID {
		return "", nil, fmt.Errorf("hookwire: row sealed to key %q, not %q", id, b.KeyID)
	}
	sk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return "", nil, err
	}
	kdf, aead := suite()
	plain, err := hpke.Open(sk, kdf, aead, b.info(), row[1+len(id):])
	if err != nil {
		return "", nil, err
	}
	if len(plain) < 2 {
		return "", nil, ErrMalformed
	}
	ct := int(binary.BigEndian.Uint16(plain))
	if len(plain) < 2+ct+4 {
		return "", nil, ErrMalformed
	}
	nb := uint64(binary.BigEndian.Uint32(plain[2+ct:]))
	if uint64(len(plain)-6-ct) < nb { // #nosec G115 -- not negative: checked just above
		return "", nil, ErrMalformed
	}
	return string(plain[2 : 2+ct]), plain[6+ct : 6+ct+int(nb)], nil // #nosec G115 -- nb is at most len(plain): checked just above
}
