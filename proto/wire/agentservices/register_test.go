// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agentservices

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"testing"
)

// The relay's check of a registration (the client's capaddr mints and
// signs it; its vectors and BIND:cap.register rows cover the codec): the
// key holder's proof holds at its relay only, for its rid only.
func TestCheckRegistration(t *testing.T) {
	pub, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	n := [RIDSize]byte{1, 2, 3}
	rid := RIDOf(n, spki)
	proof := append(binary.BigEndian.AppendUint16(n[:], uint16(len(spki))), spki...)
	proof = append(proof, ed25519.Sign(sk, RegisterMessage("relay.test", rid))...)
	if err := CheckRegistration("relay.test", rid, proof); err != nil {
		t.Fatalf("the holder's proof: %v", err)
	}
	other := rid
	other[0] ^= 1
	for name, c := range map[string]struct {
		relay string
		rid   [RIDSize]byte
		proof []byte
	}{
		"another relay": {"other.test", rid, proof},
		"another rid":   {"relay.test", other, proof},
		"truncated":     {"relay.test", rid, proof[:len(proof)-1]},
		"no relay":      {"", rid, proof},
	} {
		if CheckRegistration(c.relay, c.rid, c.proof) != ErrRegister {
			t.Errorf("%s: taken", name)
		}
	}
}
