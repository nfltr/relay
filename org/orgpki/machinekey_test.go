// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// The enrolment answer's K_m field (spec/proverif/a2a_keytransfer.pv
// queries 4-6; mutants in testdata/mutants.txt).

const mid = "m-aaaaaaaaaaaaaaaaaaaaaaaaaa"

// enrolled is one machine's redeemed token, as the issuer answers it.
type enrolled struct {
	token string // the request's token id
	cert  []byte
	key   ed25519.PrivateKey
	km    []byte
	sk    SealedKey
}

func (o *org) enrolKM(t *testing.T, name, machineID string) enrolled {
	t.Helper()
	tok, err := o.iss.MakeToken(name, []string{"web"}, machineID, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	e := enrolled{key: newKey(t), km: bytes.Repeat([]byte{7}, 32)}
	req, err := NewEnrolRequest(tok, csr(t, e.key, name))
	if err != nil {
		t.Fatal(err)
	}
	e.token = req.TokenID
	if e.cert, err = o.iss.Enrol(req, t0); err != nil {
		t.Fatal(err)
	}
	if e.sk, err = o.iss.SealMachineKey(e.token, e.cert, machineID+".1", e.km); err != nil {
		t.Fatal(err)
	}
	return e
}

func (o *org) open(e enrolled) ([]byte, error) {
	return OpenMachineKey(e.sk, e.token, e.cert, o.iss.Cert().Raw, o.rootCrt, e.key, t0)
}

// The machine's X25519 key (from its Ed25519 seed) and the issuer's image
// of its Ed25519 public key agree.
func TestX25519OfEd25519(t *testing.T) {
	for range 64 {
		k := newKey(t)
		priv, err := x25519Private(k)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := x25519Public(k.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		if !pub.Equal(priv.PublicKey()) {
			t.Fatalf("x25519Public = %x, the seed's X25519 key %x", pub.Bytes(), priv.PublicKey().Bytes())
		}
	}
	if _, err := x25519Public(make(ed25519.PublicKey, 31)); err == nil {
		t.Fatal("a 31-byte key converted")
	}
}

// Query 6 (witness): an enrolled machine opens the K_m the issuer sealed.
func TestEnrolledMachineOpensItsKey(t *testing.T) {
	o := newOrg(t)
	e := o.enrolKM(t, "web-1", mid)
	km, err := o.open(e)
	if err != nil || !bytes.Equal(km, e.km) {
		t.Fatalf("OpenMachineKey = %x, %v; want %x", km, err, e.km)
	}
}

// Query 4, mutant seal-to-request-key: the issuer seals only to a key it
// certified at that token's redemption, never to a certificate it did not
// issue, a renewal's, or another token's, and only under the certificate's
// own machine id.
func TestSealOnlyToCertifiedKey(t *testing.T) {
	o := newOrg(t)
	e := o.enrolKM(t, "web-1", mid)
	other := o.enrolKM(t, "web-2", "m-bbbbbbbbbbbbbbbbbbbbbbbbbb")

	// A certificate the relay made: the machine's id, the relay's key.
	c := parse(t, e.cert)
	forged := *c
	forged.SerialNumber = big.NewInt(42)
	forged.Subject = pkix.Name{CommonName: "web-1"}
	evil := newKey(t)
	forged.PublicKey = evil.Public()
	fder, err := x509.CreateCertificate(rand.Reader, &forged, &forged, evil.Public(), evil)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := o.iss.Renew(NewRenewRequest(e.cert, e.key, csr(t, newKey(t), "web-1")), t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, token string
		cert        []byte
		keyID       string
	}{
		{"a certificate the issuer did not issue", e.token, fder, mid + ".1"},
		{"a renewal's certificate", e.token, renewed, mid + ".1"},
		{"another token's certificate", e.token, other.cert, "m-bbbbbbbbbbbbbbbbbbbbbbbbbb.1"},
		{"another machine's key id", e.token, e.cert, "m-bbbbbbbbbbbbbbbbbbbbbbbbbb.1"},
		{"no generation", e.token, e.cert, mid},
		{"generation 0", e.token, e.cert, mid + ".0"},
	} {
		if _, err := o.iss.SealMachineKey(tc.token, tc.cert, tc.keyID, e.km); err == nil {
			t.Errorf("%s: sealed; want refused", tc.name)
		}
	}
	if _, err := o.iss.SealMachineKey(e.token, fder, mid+".1", e.km); !errors.Is(err, ErrRefused) {
		t.Errorf("a forged certificate: %v, want ErrRefused", err)
	}
}
