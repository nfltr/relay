// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The bindings nfltr's A2A key-transfer model (a2a_keytransfer.pv, kept
// with the A2A key code that uses it) relies on for the enrolment answer's
// K_m field, against the real code: each BIND:km.<id> of the model has one
// row here (kmModelIDs; nfltr's own bindings test holds the model and fails
// when its km.* ids differ from this list) that changes just that in the issuer's honest
// answer, as a relay can, and requires the machine to refuse it
// (OpenMachineKey). `make spec-bindings`.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"slices"
	"testing"
)

// kmModelIDs: the model's BIND:km.* ids.
var kmModelIDs = []string{"km.cert", "km.enc", "km.keyid", "km.rcpt", "km.sig", "km.token"}

// kmBindings: each row tampers the honest answer e of org o (o's other
// enrolled machine is x, the relay's own).
var kmBindings = map[string]func(t *testing.T, o *org, e, x *enrolled){
	"km.cert": func(_ *testing.T, _ *org, e, x *enrolled) { e.cert = x.cert },
	"km.keyid": func(_ *testing.T, _ *org, e, _ *enrolled) {
		e.sk.KeyID = mid + ".2"
	},
	"km.enc": func(t *testing.T, _ *org, e, _ *enrolled) {
		// The relay's own key, sealed to the machine's certified key.
		pub, err := x25519Public(e.key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		e.sk.Sealed = seal(t, pub, machineKeyInfo(e.cert, e.sk.KeyID), make([]byte, 32))
	},
	"km.token": func(_ *testing.T, _ *org, e, x *enrolled) { e.token = x.token },
	"km.sig": func(_ *testing.T, _ *org, e, x *enrolled) {
		e.sk.Sig = ed25519.Sign(x.key, machineKeyMessage(e.token, e.cert, e.sk))
	},
	"km.rcpt": func(t *testing.T, o *org, e, _ *enrolled) {
		// The issuer's signature over a seal to another key than the
		// certified one: only that key opens it.
		other, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		e.sk.Sealed = seal(t, other.PublicKey(), machineKeyInfo(e.cert, e.sk.KeyID), e.km)
		e.sk.Sig = ed25519.Sign(o.iss.key, machineKeyMessage(e.token, e.cert, e.sk))
	},
}

func seal(t *testing.T, pub *ecdh.PublicKey, info, km []byte) []byte {
	t.Helper()
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	kdf, aead := hpkeSuite()
	ct, err := hpke.Seal(pk, kdf, aead, info, km)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

// TestA2AKeyTransferModelBindings runs every row, and fails when the
// model's BIND ids and the rows differ.
func TestA2AKeyTransferModelBindings(t *testing.T) {
	var rows []string
	for id := range kmBindings {
		rows = append(rows, id)
	}
	slices.Sort(rows)
	if !slices.Equal(kmModelIDs, rows) {
		t.Fatalf("model BIND ids %v, rows %v: each binding of the model needs one row", kmModelIDs, rows)
	}
	for _, id := range rows {
		t.Run(id, func(t *testing.T) {
			o := newOrg(t)
			e := o.enrolKM(t, "web-1", mid)
			x := o.enrolKM(t, "evil", "m-eeeeeeeeeeeeeeeeeeeeeeeeee")
			if _, err := o.open(e); err != nil {
				t.Fatalf("the honest answer: %v", err)
			}
			kmBindings[id](t, o, &e, &x)
			if km, err := o.open(e); err == nil {
				t.Fatalf("the answer with %s changed opened to %x; want refused", id, km)
			}
		})
	}
}
