// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package orgmachinetest makes an organisation (orgpki: root, recovery,
// issuer) and enrols machines into directories of the orgmachine layout,
// for tests of organisation mode (orgmachine, transportcli, connect).
package orgmachinetest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgpki"
)

// Org is a test organisation; Groups is its issuer's policy.
type Org struct {
	Issuer  *orgpki.Issuer
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	rec     *x509.Certificate
	recKey  ed25519.PrivateKey
	dirs    []string // every machine directory, for CRL updates
}

// Groups are the groups the test issuer may issue.
var Groups = []string{"web", "db", "ci"}

// New makes an organisation at now.
func New(t testing.TB, now time.Time) *Org {
	t.Helper()
	rk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	id, err := orgpki.OrgID(rk.Public())
	check(t, err)
	root, err := orgpki.NewRoot(rk, id, now)
	check(t, err)
	_, recKey, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	rec, err := orgpki.NewRecovery(recKey, id, now)
	check(t, err)
	ipub, ikey, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	ic, err := orgpki.CertifyIssuer(root, rk, ipub, Groups, now)
	check(t, err)
	lines, err := orgpki.Genesis(root, rec, "test", orgpki.RootFile, ic, now)
	check(t, err)
	iss, err := orgpki.Open(lines, ikey, func([]byte) error { return nil })
	check(t, err)
	return &Org{Issuer: iss, root: root, rootKey: rk, rec: rec, recKey: recKey}
}

// Rotate is the owner's rotation at now: the recovery key certifies a new
// root, which certifies a new issuer. It returns the new root, the
// certificate machines take (Machine.TakeRotation).
func (o *Org) Rotate(t testing.TB, now time.Time) *x509.Certificate {
	t.Helper()
	nk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	id, err := orgid.OrgIDOfRoot(o.root)
	check(t, err)
	cross, err := orgpki.CrossSign(o.rec, o.recKey, nk.Public(), id, now)
	check(t, err)
	_, ik, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	check(t, o.Issuer.Rotate(cross, "test-2", nk, ik, Groups, now))
	o.root, o.rootKey = cross, nk
	return cross
}

func check(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Enrol enrols name in groups at now (its certificate lasts
// orgpki's machine lifetime from now) and writes its directory dir: the
// root, recovery, its certificate and key, and the issuer's CRL at now.
func (o *Org) Enrol(t testing.TB, dir, name string, now time.Time, groups ...string) *x509.Certificate {
	t.Helper()
	tok, err := o.Issuer.MakeToken(name, groups, "m-"+name, time.Hour, now)
	check(t, err)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, key)
	check(t, err)
	req, err := orgpki.NewEnrolRequest(tok, csr)
	check(t, err)
	der, err := o.Issuer.Enrol(req, now)
	check(t, err)
	host, err := o.Issuer.HostCert(der, now)
	check(t, err)
	check(t, os.MkdirAll(dir, 0o700)) // nosemgrep: incorrect-default-permission -- a directory needs x; 0o700 is owner-only
	write := func(file string, data []byte, mode os.FileMode) {
		check(t, os.WriteFile(filepath.Join(dir, file), data, mode))
	}
	cert := func(c []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c}) }
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	check(t, err)
	write(orgmachine.RootFile, cert(o.root.Raw), 0o600)
	write(orgmachine.RecoveryFile, cert(o.rec.Raw), 0o600)
	write(orgmachine.CertFile, slices.Concat(cert(der), cert(o.Issuer.Cert().Raw), pem.EncodeToMemory(&pem.Block{Type: orgmachine.HostCertBlock, Bytes: host})), 0o600)
	write(orgmachine.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0o600)
	o.dirs = append(o.dirs, dir)
	o.PublishCRL(t, now)
	c, err := x509.ParseCertificate(der)
	check(t, err)
	return c
}

// PublishCRL writes the issuer's CRL at now and its signed status (the
// access rules, Allow) into every machine directory (what orgenrol's push
// and the relay's status copy carry).
func (o *Org) PublishCRL(t testing.TB, now time.Time) {
	t.Helper()
	der, err := o.Issuer.CRL(now)
	check(t, err)
	st, err := o.Issuer.SignedStatus(now)
	check(t, err)
	msg, err := json.Marshal(st)
	check(t, err)
	for _, d := range o.dirs {
		check(t, os.WriteFile(filepath.Join(d, orgmachine.CRLFile), der, 0o600))
		check(t, os.WriteFile(filepath.Join(d, orgmachine.StatusFile), msg, 0o600))
	}
}

// Allow makes rules the organisation's access rules, as the root signs
// them (nfltr access allow), and publishes them at now.
func (o *Org) Allow(t testing.TB, now time.Time, rules ...orgid.Rule) {
	t.Helper()
	sp, err := orgpki.SignPolicy(o.rootKey, orgid.Policy{OrgID: o.Issuer.OrgID(), Number: now.UnixNano(), Rules: rules})
	check(t, err)
	_, err = o.Issuer.TakePolicy(sp, now)
	check(t, err)
	o.PublishCRL(t, now)
}

// Revoke revokes name and publishes the new CRL.
func (o *Org) Revoke(t testing.TB, name string, now time.Time) {
	t.Helper()
	check(t, o.Issuer.Revoke(name, now))
	o.PublishCRL(t, now)
}
