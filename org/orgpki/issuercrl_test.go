// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// The root's CRL of issuers (OrgHosted.tla RevokeIssuer, Deliver): the
// issuer it lists admits no machine at a verifier that took it; a re-sign
// keeps every entry under a higher Number; the root lists only issuers it
// certified, and builds only on its own CRL (mutant issuer-crl-drops-prev).
func TestSignIssuerCRL(t *testing.T) {
	o := newOrg(t)
	web, _ := o.enrol(t, "web-1", "web")
	at := t0.Add(time.Minute)
	o.takeCRL(t, at)
	first, err := SignIssuerCRL(o.rootCrt, o.root, nil, []*x509.Certificate{o.iss.Cert()}, at)
	noErr(t, err)
	again, err := SignIssuerCRL(o.rootCrt, o.root, first, nil, at.Add(time.Hour))
	noErr(t, err)
	c, err := x509.ParseRevocationList(again)
	noErr(t, err)
	if c.Number.Int64() != 2 || len(c.RevokedCertificateEntries) != 1 || c.RevokedCertificateEntries[0].SerialNumber.Cmp(o.iss.Cert().SerialNumber) != 0 {
		t.Fatalf("re-signed: number %v, entries %v", c.Number, c.RevokedCertificateEntries)
	}
	noErr(t, o.ver.TakeIssuerCRL(again))
	if _, err := o.ver.Check(web, o.iss.Cert(), orgid.Peer{Name: "web-1"}, at); err == nil {
		t.Fatal("web-1 under the revoked issuer admitted")
	}
	refused(t, "an older CRL of issuers", o.ver.TakeIssuerCRL(first))
	noErr(t, RefuseRevoked(nil, o.iss.Cert()))
	refused(t, "renewing a revoked issuer", RefuseRevoked(again, o.iss.Cert()))
	certs, err := IssuerCerts(o.lines)
	noErr(t, err)
	if len(certs) != 1 || certs[0].SerialNumber.Cmp(o.iss.Cert().SerialNumber) != 0 {
		t.Fatalf("issuer certificates in the log: %d", len(certs))
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	noErr(t, err)
	rogueRoot, err := NewRoot(other, o.iss.OrgID(), t0)
	noErr(t, err)
	_, err = SignIssuerCRL(o.rootCrt, o.root, nil, []*x509.Certificate{rogueRoot}, at)
	refused(t, "a certificate the root did not certify", err)
	rogue, err := SignIssuerCRL(rogueRoot, other, nil, nil, at)
	noErr(t, err)
	_, err = SignIssuerCRL(o.rootCrt, o.root, rogue, nil, at)
	refused(t, "building on another root's CRL", err)
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
