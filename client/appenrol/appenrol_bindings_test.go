// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package appenrol

// The sign-in nonce's binding of spec/proverif/app_enrol.pv
// (BIND:app.nonce): a token whose nonce names the device's keys is taken
// for those keys only; the relay that carries it swaps either key, or
// their order, and is refused (mutants no-nonce-check,
// nonce-relay-key-only). `make spec-bindings`.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
)

func keys(t *testing.T) (relay, org, other crypto.PublicKey) {
	t.Helper()
	rk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ok, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return rk.Public(), ok, xk
}

var appEnrolBindings = map[string]func(t *testing.T){
	"app.nonce": func(t *testing.T) {
		kr, ko, kx := keys(t)
		n, err := Nonce(kr, ko)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckNonce(n, kr, ko); err != nil {
			t.Fatalf("honest: %v", err)
		}
		for what, ks := range map[string][2]crypto.PublicKey{
			"org key swapped":   {kr, kx},
			"relay key swapped": {kx, ko},
			"keys reordered":    {ko, kr},
		} {
			if err := CheckNonce(n, ks[0], ks[1]); !errors.Is(err, ErrNonce) {
				t.Errorf("%s: %v, want ErrNonce", what, err)
			}
		}
	},
}

// TestAppEnrolModelBindingsNonce runs every row; each is a BIND id of the
// model.
func TestAppEnrolModelBindingsNonce(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/app_enrol.pv")
	if err != nil {
		t.Fatal(err)
	}
	for id, row := range appEnrolBindings {
		if !strings.Contains(string(src), "BIND:"+id+" ") {
			t.Errorf("app_enrol.pv declares no BIND:%s", id)
		}
		t.Run(id, row)
	}
}

// The nonce is a fixed encoding: a vector, so a second implementation (a
// mobile app's) can check itself against this one.
func TestNonceVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	a := ed25519.NewKeyFromSeed(seed).Public()
	seed[0] = 1
	b := ed25519.NewKeyFromSeed(seed).Public()
	n, err := Nonce(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if n != nonceVector {
		t.Fatalf("Nonce = %s, want %s", n, nonceVector)
	}
}
