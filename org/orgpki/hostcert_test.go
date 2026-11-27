// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"golang.org/x/crypto/ssh"
)

// hostCert enrols name and signs its host certificate.
func (o *org) hostCert(t *testing.T, name string) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	leaf, k := o.enrol(t, name, "web")
	raw, err := o.iss.HostCert(leaf.Raw, t0)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, k, raw
}

// The host certificate restates the machine certificate: its key, its DNS
// name as the only principal, from its NotBefore until HostLife after its
// issue or the certificate's NotAfter if sooner, under the issuer's key.
func TestHostCertRestatesMachineCert(t *testing.T) {
	o := newOrg(t)
	leaf, _, raw := o.hostCert(t, "web-1")
	c, err := CheckHostCert(raw, leaf, o.iss.Cert())
	if err != nil {
		t.Fatal(err)
	}
	want := orgid.MachineDNS("web-1", o.iss.OrgID())
	if len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != want || c.KeyId != "web-1" {
		t.Fatalf("principals %v key id %q, want [%s]", c.ValidPrincipals, c.KeyId, want)
	}
	until := leaf.NotBefore.Add(issueBackdate + HostLife)
	if leaf.NotAfter.Before(until) {
		until = leaf.NotAfter
	}
	if !time.Unix(int64(c.ValidAfter), 0).Equal(leaf.NotBefore) || !time.Unix(int64(c.ValidBefore), 0).Equal(until) { // #nosec G115 -- test
		t.Fatalf("valid %d to %d, want %s to %s", c.ValidAfter, c.ValidBefore, leaf.NotBefore, until)
	}
}

// Step A of ORGCERT72b (MachineLife still 24 h): every host certificate an
// issuer signs passes the check of the clients before it, which wanted
// the machine certificate's exact lifetime, so they keep renewing
// (spec/enrol/CertRideDay.cfg). Deleted by step B (MachineLife 72 h), which
// lands only once step A has reached every machine.
func TestStepAHostCertPassesTheOldCheck(t *testing.T) {
	o := newOrg(t)
	leaf, _, raw := o.hostCert(t, "web-1")
	k, err := ssh.ParsePublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := k.(*ssh.Certificate)
	// The lifetime case of CheckHostCert before ORGCERT72b, verbatim.
	if c.ValidAfter != uint64(leaf.NotBefore.Unix()) || c.ValidBefore != uint64(leaf.NotAfter.Unix()) { // #nosec G115 -- certificate times
		t.Fatalf("the host certificate's lifetime is not the machine certificate's: a client before ORGCERT72b refuses it")
	}
}

// The host certificate keeps a life of its own, at most HostLife (24 h)
// after its issue: OpenSSH reads no CRL, so its life bounds how long ssh
// trusts a revoked machine with every CRL withheld (spec/enrol/CertRide.tla
// HostRevokeBound). The machine's check refuses one that outlives HostLife
// or the machine certificate (mutant host-check-any-life), also for a
// machine certificate longer than HostLife.
func TestHostCertLifeIsItsOwn(t *testing.T) {
	if HostLife > 24*time.Hour {
		t.Fatalf("HostLife %s: at most 24 h", HostLife)
	}
	o := newOrg(t)
	leaf, _, raw := o.hostCert(t, "web-1")
	// The same machine certificate, three days long, signed by the issuer.
	tmpl := *leaf
	tmpl.NotAfter = leaf.NotBefore.Add(72 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, o.iss.Cert(), leaf.PublicKey, o.iss.key)
	if err != nil {
		t.Fatal(err)
	}
	long, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ssh.ParsePublicKey(raw)
	ca, _ := ssh.NewSignerFromKey(o.iss.key)
	resign := func(validBefore time.Time) []byte {
		c := *k.(*ssh.Certificate)
		c.ValidBefore = uint64(validBefore.Unix()) // #nosec G115 -- test
		if err := c.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		return c.Marshal()
	}
	if _, err := CheckHostCert(resign(long.NotBefore.Add(issueBackdate+HostLife)), long, o.iss.Cert()); err != nil {
		t.Fatalf("a host certificate of HostLife: %v", err)
	}
	_, err = CheckHostCert(resign(long.NotAfter), long, o.iss.Cert())
	refused(t, "a host certificate as long as a 72 h machine certificate", err)
	_, err = CheckHostCert(resign(leaf.NotAfter.Add(time.Hour)), leaf, o.iss.Cert())
	refused(t, "a host certificate past the machine certificate", err)
}

// A certificate for another machine's name is refused: by the issuer
// (only certificates of its log, as issued), by the machine's check, and
// by an SSH client that asks for the other name (mutants
// hostcert-not-from-log, hostcert-any-principal).
func TestHostCertForAnotherNameRefused(t *testing.T) {
	o := newOrg(t)
	_, _, raw := o.hostCert(t, "web-1")
	other, _, _ := o.hostCert(t, "web-2")

	// A certificate the issuer did not issue, for web-2's name and an
	// attacker's key, signed by another key: not in the log.
	evilKey := newKey(t)
	forged := *other
	forged.PublicKey = evilKey.Public()
	der, err := x509.CreateCertificate(rand.Reader, &forged, &forged, evilKey.Public(), evilKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = o.iss.HostCert(der, t0)
	refused(t, "host certificate of a certificate not in the log", err)

	// web-1's host certificate presented as web-2's.
	_, err = CheckHostCert(raw, other, o.iss.Cert())
	refused(t, "web-1's host certificate for web-2", err)

	// An SSH client (OpenSSH's checks: the CA, the principal) that names
	// web-2 refuses web-1's certificate; naming web-1, it takes it.
	ca, err := HostCA(o.iss.Cert())
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.ParsePublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	checker := ssh.CertChecker{
		IsHostAuthority: func(a ssh.PublicKey, _ string) bool { return string(a.Marshal()) == string(ca.Marshal()) },
		Clock:           func() time.Time { return t0.Add(time.Minute) },
	}
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
	if err := checker.CheckHostKey(orgid.MachineDNS("web-2", o.iss.OrgID())+":22", addr, k); err == nil {
		t.Fatal("an SSH client asking for web-2 took web-1's host certificate")
	}
	if err := checker.CheckHostKey(orgid.MachineDNS("web-1", o.iss.OrgID())+":22", addr, k); err != nil {
		t.Fatalf("web-1's own host certificate: %v", err)
	}
}

// A revoked or expired name gets no host certificate (Enrol.tla
// NoRenewAfterRevoke, the same refusals as a renewal).
func TestHostCertRevokedOrExpiredRefused(t *testing.T) {
	o := newOrg(t)
	leaf, _ := o.enrol(t, "web-1", "web")
	_, err := o.iss.HostCert(leaf.Raw, t0.Add(MachineLife))
	refused(t, "host certificate of an expired certificate", err)
	if err := o.iss.Revoke("web-1", t0); err != nil {
		t.Fatal(err)
	}
	_, err = o.iss.HostCert(leaf.Raw, t0)
	refused(t, "host certificate of a revoked name", err)
}

// The machine's check refuses a host certificate not signed by the issuer,
// or for another key (mutants hostcert-any-signer, hostcert-any-key).
func TestCheckHostCertRefusesOtherSignerOrKey(t *testing.T) {
	o := newOrg(t)
	leaf, _, raw := o.hostCert(t, "web-1")
	k, _ := ssh.ParsePublicKey(raw)
	c := *k.(*ssh.Certificate)
	evil, _ := ssh.NewSignerFromKey(newKey(t))
	if err := c.SignCert(rand.Reader, evil); err != nil {
		t.Fatal(err)
	}
	_, err := CheckHostCert(c.Marshal(), leaf, o.iss.Cert())
	refused(t, "a host certificate signed by another key", err)

	c = *k.(*ssh.Certificate)
	other, _ := ssh.NewPublicKey(newKey(t).Public())
	c.Key = other
	ca, _ := ssh.NewSignerFromKey(o.iss.key)
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	_, err = CheckHostCert(c.Marshal(), leaf, o.iss.Cert())
	refused(t, "a host certificate for another key", err)
}

// A host certificate naming more than the machine (signed by the issuer's
// key, say by a bug) is refused: its principals are exactly the machine's
// DNS name (mutant hostcert-extra-principal).
func TestCheckHostCertRefusesExtraPrincipal(t *testing.T) {
	o := newOrg(t)
	leaf, _, raw := o.hostCert(t, "web-1")
	k, _ := ssh.ParsePublicKey(raw)
	c := *k.(*ssh.Certificate)
	c.ValidPrincipals = append(c.ValidPrincipals, orgid.MachineDNS("web-2", o.iss.OrgID()))
	ca, _ := ssh.NewSignerFromKey(o.iss.key)
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	_, err := CheckHostCert(c.Marshal(), leaf, o.iss.Cert())
	refused(t, "a host certificate naming web-2 too", err)
}
