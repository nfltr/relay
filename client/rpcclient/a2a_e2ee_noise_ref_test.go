// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// E2EEPROOF2: the wire vectors checked against an independent Noise
// implementation. The code's handshake is github.com/flynn/noise; this is
// Noise_NNpsk0_25519_AESGCM_SHA256 written from the specification
// (Noise Protocol Framework rev. 34, §5 and §9) on the standard library
// alone, so a bug shared with the code's Noise library cannot hide here.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// refNoise is Noise's SymmetricState and CipherState (§5.1, §5.2).
type refNoise struct {
	ck, h, k []byte
	n        uint64
}

func newRefNoise(name string, prologue []byte) *refNoise {
	h := make([]byte, sha256.Size) // name padded with zeros (len(name) <= HASHLEN), else HASH(name)
	if copy(h, name) < len(name) {
		sum := sha256.Sum256([]byte(name))
		h = sum[:]
	}
	s := &refNoise{ck: h, h: h}
	s.mixHash(prologue)
	return s
}

func refHMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// refHKDF is Noise's HKDF (§4.3): two or three outputs.
func refHKDF(ck, ikm []byte, n int) [][]byte {
	tk := refHMAC(ck, ikm)
	o1 := refHMAC(tk, []byte{1})
	o2 := refHMAC(tk, append(append([]byte(nil), o1...), 2))
	if n == 2 {
		return [][]byte{o1, o2}
	}
	return [][]byte{o1, o2, refHMAC(tk, append(append([]byte(nil), o2...), 3))}
}

func (s *refNoise) mixHash(data []byte) {
	h := sha256.Sum256(append(append([]byte(nil), s.h...), data...))
	s.h = h[:]
}

func (s *refNoise) mixKey(ikm []byte) {
	o := refHKDF(s.ck, ikm, 2)
	s.ck, s.k, s.n = o[0], o[1], 0
}

func (s *refNoise) mixKeyAndHash(ikm []byte) {
	o := refHKDF(s.ck, ikm, 3)
	s.ck = o[0]
	s.mixHash(o[1])
	s.k, s.n = o[2], 0
}

// refSeal is AESGCM's ENCRYPT (§12.4): nonce = 32 zero bits, then n big-endian.
func refSeal(k []byte, n uint64, ad, pt []byte) []byte {
	b, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return g.Seal(nil, binary.BigEndian.AppendUint64(make([]byte, 4), n), pt, ad)
}

func (s *refNoise) encryptAndHash(pt []byte) []byte {
	ct := refSeal(s.k, s.n, s.h, pt)
	s.n++
	s.mixHash(ct)
	return ct
}

func refX25519(priv, pub []byte) []byte {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	p, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	out, err := k.ECDH(p)
	if err != nil {
		panic(err)
	}
	return out
}

func refPub(priv []byte) []byte {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

// TestA2AE2EEv2VectorsIndependentNoise derives the handshake and the first
// frames of TestA2AE2EEv2Vectors with refNoise and compares them byte for
// byte with what the code (flynn/noise) puts on the wire.
func TestA2AE2EEv2VectorsIndependentNoise(t *testing.T) {
	key := bytes.Repeat([]byte{0x4b}, 32)
	kr := testMachine{id: "m1.1", key: key}
	const txn, caller, callee = "txn-1", "hub-1", "m1-node"
	x, y := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)

	// The code's side.
	c := newA2AE2EEState(txn, caller, callee, testRootOf{kr})
	c.rng = fixedReader(0x11)
	init, err := c.initMessage()
	if err != nil {
		t.Fatal(err)
	}
	s, ack, err := newServerA2AE2EEState(txn, callee, init, kr, true, fixedReader(0x22))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.complete(ack); err != nil {
		t.Fatal(err)
	}
	f1, _ := c.seal(a2aFrameData, []byte("hello"))
	f2, _ := c.seal(a2aFrameEnd, nil)
	r1, _ := s.seal(a2aFrameData, []byte("world"))

	// The reference: -> psk, e; <- e, ee (payloads: none, the session offer).
	ref := newRefNoise("Noise_NNpsk0_25519_AESGCM_SHA256", a2aE2EEPrologue(txn, a2aE2EERoleRoot, caller, callee, kr.id))
	ref.mixKeyAndHash(a2aE2EEPsk(key))
	e := refPub(x)
	ref.mixHash(e)
	ref.mixKey(e) // psk handshakes mix e into the key too (§9.2)
	msg1 := append(append([]byte(nil), e...), ref.encryptAndHash(nil)...)
	re := refPub(y)
	ref.mixHash(re)
	ref.mixKey(re)
	ref.mixKey(refX25519(y, e))
	msg2 := append(append([]byte(nil), re...), ref.encryptAndHash(a2aSessionOffer)...)
	split := refHKDF(ref.ck, nil, 2)
	i2r, r2i := split[0], split[1]

	check := func(name string, got, want []byte) {
		t.Helper()
		if !bytes.Equal(got, want) {
			t.Errorf("%s:\n code      %x\n reference %x", name, got, want)
		}
	}
	check("init", init, append([]byte(caller+"\x00"+callee+"\x00"+kr.id+"\x00"), msg1...))
	check("ack", ack, msg2)
	check("caller frame 0", f1, refSeal(i2r, 0, []byte(txn), append([]byte{a2aFrameData}, "hello"...)))
	check("caller frame 1", f2, refSeal(i2r, 1, []byte(txn), []byte{a2aFrameEnd}))
	check("callee frame 0", r1, refSeal(r2i, 0, []byte(txn), append([]byte{a2aFrameData}, "world"...)))
}
