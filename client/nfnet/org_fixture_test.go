// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
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

	"github.com/nfltr/relay/client/orgid"
)

// testOrg is a throwaway organisation in nfltr's certificate profile (as
// orgid's own tests make one): a root, its recovery, an issuer for the
// groups web, db and ci, machine directories as nfltr org join writes them
// and the issuer's CRLs. Machines are *orgid.Identity loaded from them.
type testOrg struct {
	t       *testing.T
	orgID   string
	rootKey *ecdsa.PrivateKey
	root    *x509.Certificate
	rec     *x509.Certificate
	issKey  ed25519.PrivateKey
	iss     *x509.Certificate
	crlNum  int64
	revoked []*big.Int
	dirs    []string
	ids     []*orgid.Identity
	certs   map[string]*x509.Certificate
}

// must is v, or a panic (a broken fixture) for err.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func newTestOrg(t *testing.T) *testOrg {
	rk := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	sum := sha256.Sum256(must(x509.MarshalPKIXPublicKey(rk.Public())))
	o := &testOrg{t: t, orgID: fmt.Sprintf("o-%x", sum[:13]), rootKey: rk, certs: map[string]*x509.Certificate{}}
	now := time.Now()
	o.root = o.mint(o.ca("nfltr org "+o.orgID, now), nil, rk.Public(), rk)
	_, recKey, _ := ed25519.GenerateKey(rand.Reader)
	rt := o.ca("nfltr org "+o.orgID+" recovery", now)
	rt.KeyUsage = x509.KeyUsageCertSign
	o.rec = o.mint(rt, nil, recKey.Public(), recKey)
	_, o.issKey, _ = ed25519.GenerateKey(rand.Reader)
	it := o.ca("nfltr org "+o.orgID+" issuer", now)
	it.Subject.OrganizationalUnit = []string{"web", "db", "ci"}
	it.MaxPathLen, it.MaxPathLenZero = 0, true
	it.PermittedDNSDomainsCritical, it.PermittedDNSDomains = true, []string{orgid.Domain(o.orgID)}
	o.iss = o.mint(it, o.root, o.issKey.Public(), o.rootKey)
	return o
}

func (o *testOrg) ca(cn string, at time.Time) *x509.Certificate {
	return &x509.Certificate{SerialNumber: o.serial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: at.Add(-time.Minute), NotAfter: at.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1}
}

func (o *testOrg) serial() *big.Int {
	return must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)))
}

// mint is tmpl signed by signer as parent (nil: self-signed).
func (o *testOrg) mint(tmpl, parent *x509.Certificate, pub any, signer any) *x509.Certificate {
	if parent == nil {
		parent = tmpl
	}
	der := must(x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer))
	return must(x509.ParseCertificate(der))
}

// machine enrols name in groups into a directory of its own and loads it.
func (o *testOrg) machine(t *testing.T, name string, groups ...string) *orgid.Identity {
	now := time.Now()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	c := o.mint(&x509.Certificate{
		SerialNumber: o.serial(), Subject: pkix.Name{CommonName: name, OrganizationalUnit: slices.Clone(groups)},
		DNSNames:  []string{orgid.MachineDNS(name, o.orgID)},
		URIs:      []*url.URL{{Scheme: "nfltr", Host: orgid.Domain(o.orgID), Path: "/machine/m-" + name}},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}, o.iss, k.Public(), o.issKey)
	o.certs[name] = c
	dir := filepath.Join(t.TempDir(), name)
	ok(os.MkdirAll(dir, 0o700)) // nosemgrep: incorrect-default-permission -- a directory needs x; 0o700 is owner-only
	pem1 := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	write := func(file string, data []byte) { ok(os.WriteFile(filepath.Join(dir, file), data, 0o600)) }
	write(orgid.RootFile, pem1(o.root.Raw))
	write(orgid.RecoveryFile, pem1(o.rec.Raw))
	write(orgid.CertFile, slices.Concat(pem1(c.Raw), pem1(o.iss.Raw)))
	write(orgid.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: must(x509.MarshalPKCS8PrivateKey(k))}))
	o.dirs = append(o.dirs, dir)
	o.publishCRL()
	id := must(orgid.Load(dir))
	o.ids = append(o.ids, id)
	return id
}

// publishCRL writes the issuer's next CRL into every machine directory.
func (o *testOrg) publishCRL() {
	now := time.Now()
	o.crlNum++
	var entries []x509.RevocationListEntry
	for _, sn := range o.revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: sn, RevocationTime: now})
	}
	der := must(x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(o.crlNum),
		ThisUpdate: now.Add(-time.Second), NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: entries}, o.iss, o.issKey))
	for _, d := range o.dirs {
		ok(os.WriteFile(filepath.Join(d, orgid.CRLFile), der, 0o600))
	}
}

// revoke revokes name and has every machine read the new CRL (Changed
// fires on each).
func (o *testOrg) revoke(name string) {
	o.revoked = append(o.revoked, o.certs[name].SerialNumber)
	o.publishCRL()
	for _, id := range o.ids {
		must(id.Reload(time.Now()))
	}
}

// ok panics (a broken fixture) on err.
func ok(err error) { must(0, err) }
