// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"
)

// checkRotation: a new root is the recovery key's certificate of the
// organisation's root name (enrol.pv query 8, mutant rotate-by-primary),
// a CA, newer than the root it replaces, for another key.
func checkRotation(c, recovery, current *x509.Certificate, orgID string) error {
	if err := c.CheckSignatureFrom(recovery); err != nil {
		return fmt.Errorf("not signed by the recovery key: %w", err)
	}
	if id, err := OrgIDOfRoot(c); err != nil || id != orgID {
		return fmt.Errorf("not a root of %s", orgID)
	}
	if !c.IsCA || !c.BasicConstraintsValid {
		return errors.New("not a CA")
	}
	if !c.NotBefore.After(current.NotBefore) {
		return errors.New("not newer than the current root (a replayed rotation)")
	}
	if bytes.Equal(c.RawSubjectPublicKeyInfo, current.RawSubjectPublicKeyInfo) {
		return errors.New("the same key as the current root")
	}
	return nil
}

type crlState struct {
	number  *big.Int
	next    time.Time
	revoked map[string]bool // serials, by their big.Int text
}

// Verifier is the check every client and service runs on an organisation
// peer (nfltr's decision doc "Formats", Verifier check): the chain to the root it
// trusts (with the issuer's name constraints and NotAfter), the name, the
// groups, and the issuer's current CRL. It fails closed: no CRL, or one
// past its NextUpdate, admits nothing under that issuer.
type Verifier struct {
	mu       sync.Mutex
	orgID    string
	root     *x509.Certificate
	recovery *x509.Certificate
	crls     map[string]*crlState // by issuer key fingerprint
}

// NewVerifier pins an organisation from its root's and recovery's
// fingerprints (the first-use values provisioned with a token) and their
// certificates (fetched through the relay, checked here).
func NewVerifier(root, recovery *x509.Certificate, rootFP, recoveryFP string) (*Verifier, error) {
	if Fingerprint(root) != rootFP || Fingerprint(recovery) != recoveryFP {
		return nil, errors.New("the root or recovery certificate is not the pinned one")
	}
	orgID, err := OrgIDOfRoot(root)
	if err != nil {
		return nil, err
	}
	if err := recovery.CheckSignatureFrom(recovery); err != nil {
		return nil, fmt.Errorf("recovery certificate: %w", err)
	}
	if recovery.Subject.CommonName != rootCNPrefix+orgID+recoverySuffix {
		return nil, errors.New("the recovery certificate is not this organisation's")
	}
	return &Verifier{orgID: orgID, root: root, recovery: recovery, crls: map[string]*crlState{}}, nil
}

// verify checks c's chain to the root the verifier trusts (its one anchor),
// through issuer when c is a leaf: signatures, NotAfter, the issuer's
// NameConstraints, and dnsName when given. Callers hold mu.
func (v *Verifier) verify(c, issuer *x509.Certificate, dnsName string, now time.Time) ([][]*x509.Certificate, error) {
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(v.root)
	if issuer != nil {
		inter.AddCert(issuer)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: dnsName, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	return c.Verify(opts)
}

// TakeCRL takes issuer's CRL: signed by an issuer under the trusted root,
// newer than the one held (Enrol.tla accept-older-crl), not lapsed.
func (v *Verifier) TakeCRL(der []byte, issuer *x509.Certificate, now time.Time) error {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := v.verify(issuer, nil, "", now); err != nil {
		return fmt.Errorf("CRL issuer: %w", err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL: %w", err)
	}
	if crl.Number == nil {
		return errors.New("CRL has no number")
	}
	if !now.Before(crl.NextUpdate) {
		traceLine(map[string]any{"ev": "take", "v": fmt.Sprintf("%p", v), "k": KeyFingerprint(issuer.PublicKey), "num": crl.Number.Int64(), "next": crl.NextUpdate.Unix(), "t": now.Unix(), "rev": []string{}, "ok": false})
		return errors.New("CRL is past its NextUpdate")
	}
	fp := KeyFingerprint(issuer.PublicKey)
	rev := []string{}
	for _, e := range crl.RevokedCertificateEntries {
		rev = append(rev, hex.EncodeToString(e.SerialNumber.Bytes()))
	}
	line := map[string]any{"ev": "take", "v": fmt.Sprintf("%p", v), "k": fp, "num": crl.Number.Int64(), "next": crl.NextUpdate.Unix(), "t": now.Unix(), "rev": rev, "ok": false}
	if held := v.crls[fp]; held != nil && crl.Number.Cmp(held.number) <= 0 {
		traceLine(line)
		return fmt.Errorf("CRL %s is not newer than the one held (%s): a replay", crl.Number, held.number)
	}
	s := &crlState{number: crl.Number, next: crl.NextUpdate, revoked: map[string]bool{}}
	for _, e := range crl.RevokedCertificateEntries {
		s.revoked[e.SerialNumber.String()] = true
	}
	v.crls[fp] = s
	line["ok"] = true
	traceLine(line)
	return nil
}

// TakeRotation takes a new root: the recovery key's cross-signed
// certificate. The old root, its issuers and their CRLs are dropped, so
// nothing under it checks again (Enrol.tla keep-old-root).
func (v *Verifier) TakeRotation(der []byte) error {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := checkRotation(c, v.recovery, v.root, v.orgID); err != nil {
		return err
	}
	v.root, v.crls = c, map[string]*crlState{}
	traceLine(map[string]any{"ev": "rotate", "v": fmt.Sprintf("%p", v)})
	return nil
}

// Peer is what a verifier asks of a peer: Name, a client's (the machine it
// dials; "" for a service); Group, a service's required group ("" for a
// client).
type Peer struct {
	Name  string
	Group string
}

// Checked is a checked peer. Until is when the check lapses (the earlier
// of the certificate's NotAfter and the CRL's NextUpdate): a session ends
// then (Enrol.tla Tick).
type Checked struct {
	Name      string
	Groups    []string
	MachineID string
	Serial    *big.Int
	Until     time.Time
}

// Check verifies a peer's certificate and its issuer at now.
func (v *Verifier) Check(leaf, issuer *x509.Certificate, want Peer, now time.Time) (Checked, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	id, why, err := v.check(leaf, issuer, want, now)
	k := ""
	if issuer != nil {
		k = KeyFingerprint(issuer.PublicKey)
	}
	traceLine(map[string]any{"ev": "check", "v": fmt.Sprintf("%p", v), "k": k, "s": hex.EncodeToString(leaf.SerialNumber.Bytes()),
		"exp": leaf.NotAfter.Unix(), "t": now.Unix(), "ok": err == nil, "why": why})
	return id, err
}

// check is Check under mu; why classifies a refusal for the trace (Enrol.tla
// Valid: expired, nocrl, lapsed, revoked; chain, name, group: outside it).
func (v *Verifier) check(leaf, issuer *x509.Certificate, want Peer, now time.Time) (Checked, string, error) {
	dnsName := ""
	if want.Name != "" {
		dnsName = MachineDNS(want.Name, v.orgID)
	}
	chains, err := v.verify(leaf, issuer, dnsName, now)
	if err != nil {
		if !now.Before(leaf.NotAfter) {
			return Checked{}, "expired", err
		}
		return Checked{}, "chain", err
	}
	if want.Name != "" && leaf.Subject.CommonName != want.Name {
		return Checked{}, "name", fmt.Errorf("the certificate names %q, not %q", leaf.Subject.CommonName, want.Name)
	}
	iss := chains[0][len(chains[0])-2]
	groups := leaf.Subject.OrganizationalUnit
	if !subset(groups, iss.Subject.OrganizationalUnit) {
		return Checked{}, "group", fmt.Errorf("groups %v are outside the issuer's policy %v", groups, iss.Subject.OrganizationalUnit)
	}
	if want.Group != "" && !slices.Contains(groups, want.Group) {
		return Checked{}, "group", fmt.Errorf("%s is not in group %s", leaf.Subject.CommonName, want.Group)
	}
	crl := v.crls[KeyFingerprint(iss.PublicKey)]
	if crl == nil {
		return Checked{}, "nocrl", errors.New("no CRL of the issuer: fail closed")
	}
	if !now.Before(crl.next) {
		return Checked{}, "lapsed", errors.New("the issuer's CRL lapsed: fail closed")
	}
	if crl.revoked[leaf.SerialNumber.String()] {
		return Checked{}, "revoked", fmt.Errorf("%s is revoked", leaf.Subject.CommonName)
	}
	until := leaf.NotAfter
	if crl.next.Before(until) {
		until = crl.next
	}
	return Checked{Name: leaf.Subject.CommonName, Groups: slices.Clone(groups), MachineID: MachineID(leaf), Serial: leaf.SerialNumber, Until: until}, "", nil
}

// Issued checks a certificate an issuer answered: it chains (through
// issuer) to the root v trusts and is not expired at now. A machine takes
// no other answer: a relay can hand it none of its own.
func (v *Verifier) Issued(leaf, issuer *x509.Certificate, now time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, err := v.verify(leaf, issuer, "", now)
	return err
}

// Root is the root v trusts now.
func (v *Verifier) Root() *x509.Certificate {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.root
}
