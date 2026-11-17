// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/nfltr/relay/org/orgpki"
)

// The root's machine keeps every issuer certificate it signs for an
// issuer elsewhere (OrgHosted.tla Renew, mutant sign-forgets), and an
// issuer's machine keeps a CRL of issuers a renewal's answer carries only
// when it is the root's and newer than the one held (RootCRLCurrent).
func TestStoreKeepsSignedIssuersAndNewerIssuerCRLs(t *testing.T) {
	newRoot := func() (*x509.Certificate, *ecdsa.PrivateKey) {
		rk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		check(t, err)
		id, err := orgpki.OrgID(rk.Public())
		check(t, err)
		root, err := orgpki.NewRoot(rk, id, t0)
		check(t, err)
		return root, rk
	}
	root, rk := newRoot()
	s, err := Lock(t.TempDir())
	check(t, err)
	defer s.Unlock()
	var serials []string
	for range 2 {
		_, ik, _ := ed25519.GenerateKey(rand.Reader)
		c, err := orgpki.CertifyIssuer(root, rk, ik.Public().(ed25519.PublicKey), []string{"web"}, t0)
		check(t, err)
		check(t, s.KeepSigned(c.Raw))
		serials = append(serials, c.SerialNumber.String())
	}
	got, err := s.Signed()
	check(t, err)
	if len(got) != 2 || got[0].SerialNumber.String() != serials[0] || got[1].SerialNumber.String() != serials[1] {
		t.Fatalf("kept %d certificates, want both in order", len(got))
	}

	first, err := orgpki.SignIssuerCRL(root, rk, nil, nil, t0)
	check(t, err)
	second, err := orgpki.SignIssuerCRL(root, rk, first, nil, t0)
	check(t, err)
	check(t, s.TakeIssuers(root, second))
	check(t, s.TakeIssuers(root, first)) // older: kept as is
	if held, _ := s.ReadIssuers(); !bytes.Equal(held, second) {
		t.Fatal("an older CRL of issuers replaced a newer one")
	}
	other, ok := newRoot()
	foreign, err := orgpki.SignIssuerCRL(other, ok, second, nil, t0)
	if err == nil {
		t.Fatal("signed over another root's CRL")
	}
	foreign, err = orgpki.SignIssuerCRL(other, ok, nil, nil, t0)
	check(t, err)
	if err := s.TakeIssuers(root, foreign); err == nil {
		t.Fatal("kept a CRL of issuers another root signed")
	}
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
