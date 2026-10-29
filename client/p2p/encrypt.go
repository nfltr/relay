// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net"
)

// encryptedConn wraps a net.Conn with AES-256-CTR stream encryption.
// All bytes written are encrypted; all bytes read are decrypted transparently.
// Each direction uses a separate IV so the two CTR streams never collide.
type encryptedConn struct {
	net.Conn
	r  io.Reader
	w  io.Writer
	id string // ConnID
}

// newEncryptedConn creates an encrypted wrapper around conn using AES-256-CTR.
// key must be 32 bytes; writeIV and readIV must be aes.BlockSize (16) bytes.
func newEncryptedConn(conn net.Conn, key, writeIV, readIV []byte) (*encryptedConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &encryptedConn{
		Conn: conn,
		r:    &cipher.StreamReader{S: cipher.NewCTR(block, readIV), R: conn},
		w:    &cipher.StreamWriter{S: cipher.NewCTR(block, writeIV), W: conn},
	}, nil
}

func (c *encryptedConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *encryptedConn) Write(p []byte) (int, error) { return c.w.Write(p) }

// deriveSessionKey computes a per-session AES-256 key and two directional IVs
// from the HMAC handshake material.  Both peers produce the same values:
//
//   - Challenges are sorted lexicographically for canonical ordering.
//   - key = HMAC-SHA256(token, "p2p-key:" || sessionID || ":" || sorted challenges)
//   - IVs are derived with direction-specific labels ("dial2accept" / "accept2dial")
//     so the two CTR streams never share a (key, IV) pair.
//   - isDialer selects which IV is for writing vs reading.
func deriveSessionKey(token []byte, sessionID string, myChallenge, theirChallenge []byte, isDialer bool) (key, writeIV, readIV []byte) {
	// Canonical ordering of challenges.
	first, second := myChallenge, theirChallenge
	if bytes.Compare(myChallenge, theirChallenge) > 0 {
		first, second = theirChallenge, myChallenge
	}

	// 32-byte AES-256 key.
	hk := hmac.New(sha256.New, token)
	hk.Write([]byte("p2p-key:"))
	hk.Write([]byte(sessionID))
	hk.Write([]byte(":"))
	hk.Write(first)
	hk.Write(second)
	key = hk.Sum(nil) // 32 bytes

	// 16-byte IV for dialer → accepter direction.
	h1 := hmac.New(sha256.New, key)
	h1.Write([]byte("p2p-iv-dial2accept"))
	ivDial := h1.Sum(nil)[:aes.BlockSize]

	// 16-byte IV for accepter → dialer direction.
	h2 := hmac.New(sha256.New, key)
	h2.Write([]byte("p2p-iv-accept2dial"))
	ivAccept := h2.Sum(nil)[:aes.BlockSize]

	if isDialer {
		return key, ivDial, ivAccept
	}
	return key, ivAccept, ivDial
}
