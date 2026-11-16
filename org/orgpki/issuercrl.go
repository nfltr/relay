// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// SignIssuerCRL is the root's CRL of issuers (RFC 5280 section 5: a CRL
// the root signs for its subordinate CA certificates; nfltr's
// org-hosted-issuer-2026-11-16 section 4): prev's entries (a CRL of
// issuers the root signed, nil for the first) and the issuer certificates
// of revoke, each one the root certified, under prev's Number plus one.
// With no revoke it re-signs prev (the monthly renewal). Machines take it
// from RootMessage.Issuers by a higher Number only and refuse every chain
// through an issuer it lists (orgid.Verifier.TakeIssuerCRL); its
// NextUpdate is informational, a revocation does not lapse.
func SignIssuerCRL(root *x509.Certificate, signer crypto.Signer, prev []byte, revoke []*x509.Certificate, now time.Time) ([]byte, error) {
	number := big.NewInt(1)
	var entries []x509.RevocationListEntry
	listed := map[string]bool{}
	if prev != nil {
		p, err := x509.ParseRevocationList(prev)
		if err != nil {
			return nil, fmt.Errorf("the CRL of issuers held: %w", err)
		}
		if err := p.CheckSignatureFrom(root); err != nil {
			return nil, fmt.Errorf("the CRL of issuers held is not this root's: %w", err)
		}
		if p.Number == nil {
			return nil, errors.New("the CRL of issuers held has no number")
		}
		number.Add(p.Number, number)
		for _, e := range p.RevokedCertificateEntries {
			entries = append(entries, x509.RevocationListEntry{SerialNumber: e.SerialNumber, RevocationTime: e.RevocationTime})
			listed[e.SerialNumber.String()] = true
		}
	}
	for _, c := range revoke {
		if !c.IsCA || c.CheckSignatureFrom(root) != nil {
			return nil, fmt.Errorf("certificate %s is not an issuer this root certified", c.SerialNumber)
		}
		if !listed[c.SerialNumber.String()] {
			entries = append(entries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: now})
			listed[c.SerialNumber.String()] = true
		}
	}
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: number, ThisUpdate: now, NextUpdate: now.Add(IssuerLife), RevokedCertificateEntries: entries,
	}, root, signer)
}

// IssuerCerts are the issuer certificates the root signed in a log
// (ActIssuer lines, oldest first): what `nfltr org issuer revoke` lists
// for a key.
func IssuerCerts(lines [][]byte) ([]*x509.Certificate, error) {
	entries, _, err := VerifyLog(lines)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, e := range entries {
		if e.Act != ActIssuer {
			continue
		}
		c, err := x509.ParseCertificate(e.Cert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// RefuseRevoked is ErrRefused when issuers, the root's CRL of issuers
// (nil: none), lists issuer c: the root renews no issuer it revoked
// (OrgHosted.tla Renew).
func RefuseRevoked(issuers []byte, c *x509.Certificate) error {
	if issuers == nil {
		return nil
	}
	crl, err := x509.ParseRevocationList(issuers)
	if err != nil {
		return err
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(c.SerialNumber) == 0 {
			return fmt.Errorf("%w: the root revoked this issuer (its CRL of issuers, number %s)", ErrRefused, crl.Number)
		}
	}
	return nil
}
