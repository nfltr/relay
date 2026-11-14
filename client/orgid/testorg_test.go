// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// A test organisation in nfltr's certificate profile: a root (an ECDSA
// key), its recovery, an issuer whose policy is groups and whose names are
// the organisation's domain, machine certificates and CRLs. The issuer itself is nfltr's; this is a stand-in
// with throwaway keys that makes what it makes.

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

const (
	machineLife = 24 * time.Hour
	crlLife     = time.Hour
)

type testOrg struct {
	orgID   string
	rootKey *ecdsa.PrivateKey
	root    *x509.Certificate
	recKey  ed25519.PrivateKey
	rec     *x509.Certificate
	issKey  ed25519.PrivateKey
	iss     *x509.Certificate
	groups  []string
	crlNum  int64
	revoked []*big.Int
	ver     *Verifier
	dirs    []string // machine directories, for CRL updates
}

func check(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func newKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	return k
}

func serialNumber(t testing.TB) *big.Int {
	t.Helper()
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	check(t, err)
	return sn
}

func mint(t testing.TB, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	check(t, err)
	c, err := x509.ParseCertificate(der)
	check(t, err)
	return c
}

func caTemplate(t testing.TB, cn string, at time.Time, life time.Duration) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: serialNumber(t), Subject: pkix.Name{CommonName: cn},
		NotBefore: at.Add(-time.Minute), NotAfter: at.Add(life),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
	}
}

// rootCert is a root of orgID under key at (signed by signer, or self).
func rootCert(t testing.TB, orgID string, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer, at time.Time) *x509.Certificate {
	tmpl := caTemplate(t, rootCNPrefix+orgID, at, 10*365*24*time.Hour)
	if parent == nil {
		parent = tmpl
	}
	return mint(t, tmpl, parent, pub, signer)
}

func newTestOrg(t testing.TB, at time.Time) *testOrg {
	t.Helper()
	rk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	spki, err := x509.MarshalPKIXPublicKey(rk.Public())
	check(t, err)
	sum := sha256.Sum256(spki)
	o := &testOrg{orgID: fmt.Sprintf("o-%x", sum[:13]), rootKey: rk, recKey: newKey(t), groups: []string{"web", "db", "ci"}}
	o.root = rootCert(t, o.orgID, rk.Public(), nil, rk, at)
	rt := caTemplate(t, rootCNPrefix+o.orgID+recoverySuffix, at, 10*365*24*time.Hour)
	rt.KeyUsage = x509.KeyUsageCertSign
	o.rec = mint(t, rt, rt, o.recKey.Public(), o.recKey)
	o.certifyIssuer(t, at)
	o.ver, err = NewVerifier(o.root, o.rec, Fingerprint(o.root), Fingerprint(o.rec))
	check(t, err)
	return o
}

// certifyIssuer makes a new issuer under the current root.
func (o *testOrg) certifyIssuer(t testing.TB, at time.Time) {
	t.Helper()
	o.issKey = newKey(t)
	tmpl := caTemplate(t, rootCNPrefix+o.orgID+" issuer", at, 30*24*time.Hour)
	tmpl.Subject.OrganizationalUnit = slices.Clone(o.groups)
	tmpl.MaxPathLen, tmpl.MaxPathLenZero = 0, true
	tmpl.PermittedDNSDomainsCritical, tmpl.PermittedDNSDomains = true, []string{Domain(o.orgID)}
	o.iss = mint(t, tmpl, o.root, o.issKey.Public(), o.rootKey)
	o.crlNum, o.revoked = 0, nil
}

// leafTemplate is a machine's leaf in the profile (domain orgID).
func leafTemplate(t testing.TB, orgID, name string, groups []string, at time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: serialNumber(t),
		Subject:      pkix.Name{CommonName: name, OrganizationalUnit: slices.Clone(groups)},
		DNSNames:     []string{MachineDNS(name, orgID)},
		URIs:         []*url.URL{{Scheme: "nfltr", Host: Domain(orgID), Path: machineURIPath + "m-" + name}},
		NotBefore:    at.Add(-time.Minute), NotAfter: at.Add(machineLife),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

// enrol is name's certificate in groups from the issuer, and its key.
func (o *testOrg) enrol(t testing.TB, name string, groups ...string) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	k := newKey(t)
	return mint(t, leafTemplate(t, o.orgID, name, groups, t0), o.iss, k.Public(), o.issKey), k
}

// crl is the issuer's next CRL at at, revoking every serial revoked so far.
func (o *testOrg) crl(t testing.TB, at time.Time) []byte {
	t.Helper()
	o.crlNum++
	var entries []x509.RevocationListEntry
	for _, sn := range o.revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: sn, RevocationTime: at})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(o.crlNum), ThisUpdate: at, NextUpdate: at.Add(crlLife), RevokedCertificateEntries: entries}, o.iss, o.issKey)
	check(t, err)
	return der
}

func (o *testOrg) takeCRL(t testing.TB, at time.Time) {
	t.Helper()
	check(t, o.ver.TakeCRL(o.crl(t, at), o.iss, at))
}

// rotate is the owner's rotation at at: the recovery key certifies a new
// root, which certifies a new issuer.
func (o *testOrg) rotate(t testing.TB, at time.Time) *x509.Certificate {
	t.Helper()
	nk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	o.root, o.rootKey = rootCert(t, o.orgID, nk.Public(), o.rec, o.recKey, at), nk
	o.certifyIssuer(t, at)
	return o.root
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// enrolDir enrols name in groups at t0 into the directory dir (the layout
// nfltr org join writes, an SSH host certificate block included) and
// publishes the issuer's CRL at now into every directory.
func (o *testOrg) enrolDir(t testing.TB, dir, name string, now time.Time, groups ...string) *x509.Certificate {
	t.Helper()
	k := newKey(t)
	c := mint(t, leafTemplate(t, o.orgID, name, groups, now), o.iss, k.Public(), o.issKey)
	check(t, os.MkdirAll(dir, 0o700)) // nosemgrep: incorrect-default-permission -- a directory needs x; 0o700 is owner-only
	pk, err := x509.MarshalPKCS8PrivateKey(k)
	check(t, err)
	write := func(file string, data []byte) { check(t, os.WriteFile(filepath.Join(dir, file), data, 0o600)) }
	write(RootFile, certPEM(o.root.Raw))
	write(RecoveryFile, certPEM(o.rec.Raw))
	write(CertFile, slices.Concat(certPEM(c.Raw), certPEM(o.iss.Raw), pem.EncodeToMemory(&pem.Block{Type: "NFLTR SSH HOST CERTIFICATE", Bytes: []byte("host")})))
	write(KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	o.dirs = append(o.dirs, dir)
	o.publishCRL(t, now)
	return c
}

// publishCRL writes the issuer's next CRL at now into every directory.
func (o *testOrg) publishCRL(t testing.TB, now time.Time) []byte {
	t.Helper()
	der := o.crl(t, now)
	for _, d := range o.dirs {
		check(t, os.WriteFile(filepath.Join(d, CRLFile), der, 0o600))
	}
	return der
}

// revoke revokes c (its serial in every later CRL).
func (o *testOrg) revoke(c *x509.Certificate) { o.revoked = append(o.revoked, c.SerialNumber) }

func load(t testing.TB, dir string) *Identity {
	t.Helper()
	m, err := Load(dir)
	check(t, err)
	return m
}

func refused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted, want refused", what)
	}
}
