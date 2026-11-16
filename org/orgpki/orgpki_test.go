// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// Each test names the model property it enforces (spec/proverif/enrol.pv
// query, spec/enrol/Enrol.tla invariant) and the planted bug in
// testdata/mutants.txt that makes it fail (scripts/go-mutants.sh).

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

type org struct {
	root    *ecdsa.PrivateKey // the Secure Enclave key's software stand-in
	rec     ed25519.PrivateKey
	iss     *Issuer
	lines   [][]byte
	ver     *orgid.Verifier
	groups  []string
	rootCrt *x509.Certificate
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newOrg(t *testing.T) *org {
	t.Helper()
	rk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	o := &org{root: rk, rec: newKey(t), groups: []string{"web", "db"}}
	id, err := OrgID(rk.Public())
	if err != nil {
		t.Fatal(err)
	}
	root, err := NewRoot(rk, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := NewRecovery(o.rec, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	ik := newKey(t)
	ic, err := CertifyIssuer(root, rk, ik.Public().(ed25519.PublicKey), o.groups, t0)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := Genesis(root, rec, "org", RootSecureEnclave, ic, t0)
	if err != nil {
		t.Fatal(err)
	}
	o.lines = lines
	if o.iss, err = Open(lines, ik, o.sink); err != nil {
		t.Fatal(err)
	}
	if o.ver, err = orgid.NewVerifier(root, rec, orgid.Fingerprint(root), orgid.Fingerprint(rec)); err != nil {
		t.Fatal(err)
	}
	o.rootCrt = root
	return o
}

func (o *org) sink(line []byte) error {
	o.lines = append(o.lines, append([]byte(nil), line...))
	return nil
}

func csr(t *testing.T, k ed25519.PrivateKey, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func parse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// enrol makes a token for name and redeems it with a fresh key.
func (o *org) enrol(t *testing.T, name string, groups ...string) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	tok, err := o.iss.MakeToken(name, groups, "m-"+name, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	req, err := NewEnrolRequest(tok, csr(t, k, name))
	if err != nil {
		t.Fatal(err)
	}
	der, err := o.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, der), k
}

func (o *org) takeCRL(t *testing.T, at time.Time) {
	t.Helper()
	der, err := o.iss.CRL(at)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeCRL(der, o.iss.Cert(), at); err != nil {
		t.Fatal(err)
	}
}

func refused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted, want refused", what)
	}
}

func TestHonestMachineChecks(t *testing.T) {
	o := newOrg(t)
	web, _ := o.enrol(t, "web-1", "web")
	o.takeCRL(t, t0)
	id, err := o.ver.Check(web, o.iss.Cert(), orgid.Peer{Name: "web-1"}, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "web-1" || id.MachineID != "m-web-1" || !id.Until.Equal(t0.Add(CRLLife)) {
		t.Fatalf("identity %+v", id)
	}
	if web.NotAfter.Sub(t0) != MachineLife || o.iss.Cert().NotAfter.Sub(t0) != IssuerLife {
		t.Fatalf("lifetimes: machine %s, issuer %s", web.NotAfter.Sub(t0), o.iss.Cert().NotAfter.Sub(t0))
	}
}

// enrol.pv 1 and 2 (no name without the root; web is web): mutants
// no-chain-check, no-name-check, no-name-constraint.
func TestForgedNameRefused(t *testing.T) {
	o := newOrg(t)
	web, _ := o.enrol(t, "web-1", "web")
	other, _ := o.enrol(t, "web-2", "web")
	o.takeCRL(t, t0)
	at := t0.Add(time.Minute)

	// A peer with web-2's real certificate is not web-1.
	_, err := o.ver.Check(other, o.iss.Cert(), orgid.Peer{Name: "web-1"}, at)
	refused(t, "web-2 as web-1", err)

	// A certificate for web-1 from an issuer the root never certified.
	rogueKey := newKey(t)
	rogueRoot, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogueCA, err := NewRoot(rogueRoot, o.iss.OrgID(), t0)
	if err != nil {
		t.Fatal(err)
	}
	rogueIss, err := CertifyIssuer(rogueCA, rogueRoot, rogueKey.Public().(ed25519.PublicKey), o.groups, t0)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, _ := machineTemplate(o.iss.OrgID(), "web-1", []string{"web"}, "", Device{}, rogueIss, t0)
	forged, err := x509.CreateCertificate(rand.Reader, tmpl, rogueIss, newKey(t).Public(), rogueKey)
	if err != nil {
		t.Fatal(err)
	}
	// The relay also carries the rogue issuer's own CRL.
	rogueCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: t0, NextUpdate: t0.Add(CRLLife)}, rogueIss, rogueKey)
	if err != nil {
		t.Fatal(err)
	}
	refused(t, "the rogue issuer's CRL", o.ver.TakeCRL(rogueCRL, rogueIss, at))
	_, err = o.ver.Check(parse(t, forged), rogueIss, orgid.Peer{Name: "web-1"}, at)
	refused(t, "web-1 under a rogue issuer", err)

	// The issuer's own key signing a name outside the organisation's domain
	// (the root's NameConstraints bound a misbehaving or stolen issuer).
	tmpl, _ = machineTemplate("o-elsewhere", "web-1", []string{"web"}, "", Device{}, o.iss.Cert(), t0)
	outside, err := x509.CreateCertificate(rand.Reader, tmpl, o.iss.Cert(), newKey(t).Public(), o.iss.key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = o.ver.Check(parse(t, outside), o.iss.Cert(), orgid.Peer{}, at)
	refused(t, "a name outside the organisation's domain", err)

	if _, err := o.ver.Check(web, o.iss.Cert(), orgid.Peer{Name: "web-1"}, at); err != nil {
		t.Fatalf("honest web-1: %v", err)
	}
}

// enrol.pv 3, Enrol.tla NoExpiredSession and renew-expired: an expired
// certificate is refused by the verifier and by the issuer's renewal.
func TestExpiredRefused(t *testing.T) {
	o := newOrg(t)
	web, k := o.enrol(t, "web-1", "web")
	late := web.NotAfter.Add(time.Second)
	o.takeCRL(t, late)
	_, err := o.ver.Check(web, o.iss.Cert(), orgid.Peer{Name: "web-1"}, late)
	refused(t, "an expired certificate", err)

	_, err = o.iss.Renew(NewRenewRequest(web.Raw, k, csr(t, newKey(t), "web-1")), late)
	refused(t, "a renewal of an expired certificate", err)
}

// Members refuse a CRL whose issuer certificate expired (orgid.Verifier.
// TakeCRL), so the issuer signs none past its NotAfter (ErrIssuerExpired)
// and commits nothing; the renewal makes the CRL due at once, as does a
// revocation: mutants sign-after-expiry, crl-not-due-on-renewal,
// crl-not-due-on-revoke.
func TestNoCRLPastTheIssuerCertificate(t *testing.T) {
	o := newOrg(t)
	o.enrol(t, "web-1", "web")
	o.takeCRL(t, t0)
	if o.iss.CRLDue() {
		t.Fatal("a CRL due right after one")
	}
	late := o.iss.Cert().NotAfter
	n, _ := o.iss.LastCRL()
	if _, err := o.iss.CRL(late); !errors.Is(err, ErrIssuerExpired) {
		t.Fatalf("a CRL past the issuer certificate: %v, want ErrIssuerExpired", err)
	}
	if m, _ := o.iss.LastCRL(); m != n || o.iss.CRLDue() {
		t.Fatalf("the refused CRL committed #%d (was #%d) or made one due", m, n)
	}
	_, ans := o.remote(t, late)
	if err := o.iss.InstallRenewal(ans, late); err != nil {
		t.Fatal(err)
	}
	if !o.iss.CRLDue() {
		t.Fatal("no CRL due under the renewed certificate")
	}
	o.takeCRL(t, late)
	if err := o.iss.Revoke("web-1", late); err != nil {
		t.Fatal(err)
	}
	if !o.iss.CRLDue() {
		t.Fatal("no CRL due after a revocation")
	}
}

// enrol.pv 4, Enrol.tla RevokedMachineRefused and NoRenewAfterRevoke:
// mutants no-crl-check, revoke-current-only, renew-revoked.
func TestRevokedRefused(t *testing.T) {
	o := newOrg(t)
	first, k := o.enrol(t, "lost", "db")
	k2 := newKey(t)
	der, err := o.iss.Renew(NewRenewRequest(first.Raw, k, csr(t, k2, "lost")), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	second := parse(t, der)
	if err := o.iss.Revoke("lost", t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(2 * time.Hour)
	o.takeCRL(t, at)
	for name, c := range map[string]*x509.Certificate{"the renewed certificate": second, "the certificate before the renewal": first} {
		_, err := o.ver.Check(c, o.iss.Cert(), orgid.Peer{Group: "db"}, at)
		refused(t, name, err)
	}
	_, err = o.iss.Renew(NewRenewRequest(second.Raw, k2, csr(t, newKey(t), "lost")), at)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("renewal after the revoke: %v, want refused", err)
	}
}

// enrol.pv 5 (a token enrols one key): mutant reusable-token.
func TestReusedTokenRefused(t *testing.T) {
	o := newOrg(t)
	tok, err := o.iss.MakeToken("new1", []string{"web"}, "", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []bool{true, false} {
		req, _ := NewEnrolRequest(tok, csr(t, newKey(t), "new1"))
		_, err := o.iss.Enrol(req, t0)
		if (err == nil) != want {
			t.Fatalf("redemption %d: err %v, want accepted=%v", i+1, err, want)
		}
	}
}

// Join.tla Issue: a token asked again for the key it enrolled (its answer
// was lost, or came after the join gave up) is answered again with a new
// certificate of that key; another key, a renewal since, or a revoke is
// refused. Mutants burn-name, reissue-any-key, reissue-after-renewal,
// reissue-revoked.
func TestTokenAnsweredAgainForItsKey(t *testing.T) {
	o := newOrg(t)
	enrolled := func(name string) (string, ed25519.PrivateKey, *x509.Certificate) {
		tok, err := o.iss.MakeToken(name, []string{"web"}, "", time.Hour, t0)
		if err != nil {
			t.Fatal(err)
		}
		k := newKey(t)
		req, _ := NewEnrolRequest(tok, csr(t, k, name))
		der, err := o.iss.Enrol(req, t0)
		if err != nil {
			t.Fatal(err)
		}
		return tok, k, parse(t, der)
	}
	again := func(tok string, k ed25519.PrivateKey, at time.Time) ([]byte, error) {
		req, _ := NewEnrolRequest(tok, csr(t, k, "x"))
		return o.iss.Enrol(req, at)
	}

	tok, k, first := enrolled("web-1")
	der, err := again(tok, k, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("the token asked again for its key: %v", err)
	}
	c := parse(t, der)
	if !c.PublicKey.(ed25519.PublicKey).Equal(k.Public()) || c.Subject.CommonName != "web-1" || c.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatalf("answered again: %q serial %v, want a new certificate of the same key for web-1", c.Subject.CommonName, c.SerialNumber)
	}
	_, err = again(tok, newKey(t), t0.Add(time.Minute))
	refused(t, "the token for another key", err)

	// A renewal since ends the token's answers: one to a new key retired
	// the token's, and one keeping the key is the name's newest
	// certificate, no longer the token's.
	if _, err := o.iss.Renew(NewRenewRequest(der, k, csr(t, k, "web-1")), t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, err = again(tok, k, t0.Add(3*time.Minute))
	refused(t, "the token's key after a renewal", err)

	// A revoked name.
	tok2, k2, _ := enrolled("web-2")
	if err := o.iss.Revoke("web-2", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, err = again(tok2, k2, t0.Add(2*time.Minute))
	refused(t, "the token of a revoked name", err)

	// An expired token is refused for its own key too.
	tok3, k3, _ := enrolled("web-3")
	_, err = again(tok3, k3, t0.Add(time.Hour))
	refused(t, "an expired token for its key", err)
}

// A token names its organisation (TokenOrgID: the id of its mailboxes,
// kept across a rotation), and a token of the v1 format, which did not, is
// refused with the cause named.
func TestTokenNamesItsOrganisation(t *testing.T) {
	o := newOrg(t)
	tok, err := o.iss.MakeToken("new1", []string{"web"}, "", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := TokenOrgID(tok); err != nil || id != o.iss.OrgID() {
		t.Fatalf("TokenOrgID %q %v, want %q", id, err, o.iss.OrgID())
	}
	id, sec, _ := strings.Cut(strings.TrimPrefix(tok, "nfltr-org-token-v2."+o.iss.OrgID()+"."), ".")
	for _, bad := range []string{"nfltr-org-token-v1." + id + "." + sec, "nfltr-org-token-v2.o-x." + id + "." + sec, "nfltr-org-token-v2." + id + "." + sec} {
		if _, err := TokenOrgID(bad); err == nil {
			t.Fatalf("TokenOrgID(%q) accepted", bad)
		}
		if _, err := NewEnrolRequest(bad, nil); err == nil {
			t.Fatalf("NewEnrolRequest(%q) accepted", bad)
		}
	}
	if _, err := NewEnrolRequest("nfltr-org-token-v1."+id+"."+sec, nil); err == nil || !strings.Contains(err.Error(), "nfltr org token") {
		t.Fatalf("a v1 token: %v, want a refusal naming nfltr org token", err)
	}
}

// enrol.pv 6 (a token enrols only its own name): mutants
// name-from-request, token-in-request (a request not bound to the token by
// its MAC), and a token for a name already enrolled.
func TestTokenForAnotherNameRefused(t *testing.T) {
	o := newOrg(t)
	tok, err := o.iss.MakeToken("new1", []string{"web"}, "", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	// The relay swaps the CSR under the token's MAC.
	req, _ := NewEnrolRequest(tok, csr(t, newKey(t), "new1"))
	req.CSR = csr(t, newKey(t), "new1")
	_, err = o.iss.Enrol(req, t0)
	refused(t, "a CSR the MAC does not bind", err)

	// The CSR asks for another name: the certificate carries the token's.
	req, _ = NewEnrolRequest(tok, csr(t, newKey(t), "web-1"))
	der, err := o.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	if c := parse(t, der); c.Subject.CommonName != "new1" || c.DNSNames[0] != orgid.MachineDNS("new1", o.iss.OrgID()) {
		t.Fatalf("certificate names %q %v, want the token's name new1", c.Subject.CommonName, c.DNSNames)
	}
	_, err = o.iss.MakeToken("new1", []string{"web"}, "", time.Hour, t0)
	refused(t, "a token for an enrolled name", err)

	// Two tokens for one name: the second cannot enrol it again.
	t2, _ := o.iss.MakeToken("new2", []string{"web"}, "", time.Hour, t0)
	t3, _ := o.iss.MakeToken("new2", []string{"web"}, "", time.Hour, t0)
	r2, _ := NewEnrolRequest(t2, csr(t, newKey(t), "new2"))
	if _, err := o.iss.Enrol(r2, t0); err != nil {
		t.Fatal(err)
	}
	r3, _ := NewEnrolRequest(t3, csr(t, newKey(t), "new2"))
	_, err = o.iss.Enrol(r3, t0)
	refused(t, "a second token for an enrolled name", err)

	// An expired token.
	t4, _ := o.iss.MakeToken("new4", []string{"web"}, "", time.Hour, t0)
	r4, _ := NewEnrolRequest(t4, csr(t, newKey(t), "new4"))
	_, err = o.iss.Enrol(r4, t0.Add(time.Hour))
	refused(t, "an expired token", err)
}

// enrol.pv 7 (a service admits only its group): mutants no-group-check,
// token-group-outside-policy, leaf-group-outside-issuer.
func TestGroupOutsidePolicyRefused(t *testing.T) {
	o := newOrg(t)
	_, err := o.iss.MakeToken("ci-1", []string{"ci"}, "", time.Hour, t0)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("a token for a group outside the issuer's policy: %v, want refused", err)
	}
	web, _ := o.enrol(t, "web-1", "web")
	o.takeCRL(t, t0)
	at := t0.Add(time.Minute)
	_, err = o.ver.Check(web, o.iss.Cert(), orgid.Peer{Group: "db"}, at)
	refused(t, "a web machine at a db service", err)

	// A leaf whose OU is outside the issuer's (an issuer bug): refused.
	tmpl, _ := machineTemplate(o.iss.OrgID(), "web-9", []string{"ci"}, "", Device{}, o.iss.Cert(), t0)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, o.iss.Cert(), newKey(t).Public(), o.iss.key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = o.ver.Check(parse(t, der), o.iss.Cert(), orgid.Peer{Name: "web-9"}, at)
	refused(t, "a group outside the issuer's policy", err)
}

// Enrol.tla RevocationBound (fail closed) and accept-older-crl, enrol.pv
// stale-crl: no CRL, a lapsed CRL and a replayed older CRL.
func TestLapsedCRLRefused(t *testing.T) {
	o := newOrg(t)
	web, _ := o.enrol(t, "web-1", "web")
	_, err := o.ver.Check(web, o.iss.Cert(), orgid.Peer{Name: "web-1"}, t0)
	refused(t, "no CRL", err)

	old, err := o.iss.CRL(t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeCRL(old, o.iss.Cert(), t0); err != nil {
		t.Fatal(err)
	}
	_, err = o.ver.Check(web, o.iss.Cert(), orgid.Peer{Name: "web-1"}, t0.Add(CRLLife))
	refused(t, "a CRL at its NextUpdate", err)
	refused(t, "taking a lapsed CRL", o.ver.TakeCRL(old, o.iss.Cert(), t0.Add(CRLLife)))

	// A revoke, then the relay replays the CRL from before it.
	at := t0.Add(10 * time.Minute)
	if err := o.iss.Revoke("web-1", at); err != nil {
		t.Fatal(err)
	}
	o.takeCRL(t, at)
	refused(t, "a replayed older CRL", o.ver.TakeCRL(old, o.iss.Cert(), at))
	_, err = o.ver.Check(web, o.iss.Cert(), orgid.Peer{Name: "web-1"}, at)
	refused(t, "the revoked machine after the replay", err)
}

func rotate(t *testing.T, o *org, at time.Time, signer ed25519.PrivateKey, signerCert *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cross, err := CrossSign(signerCert, signer, nk.Public(), o.iss.OrgID(), at)
	if err != nil {
		t.Fatal(err)
	}
	return cross, nk
}

// enrol.pv 8 and 9, Enrol.tla RootsAreOwners, SessionsOnTrustedRoot,
// MachinesFollowRotation, ForgedOnlyUnderStolenRoot: mutants
// rotate-by-primary, keep-old-root, renew-forged.
func TestRotationOnlyByRecoveryKey(t *testing.T) {
	o := newOrg(t)
	web, k := o.enrol(t, "web-1", "web")
	at := t0.Add(time.Hour)

	// The stolen primary: its "root" re-signs itself under a new key, and
	// mints a certificate for web-1 under the old root.
	thief := newKey(t)
	thiefRoot, err := NewRecovery(thief, o.iss.OrgID(), t0)
	if err != nil {
		t.Fatal(err)
	}
	evil, _ := rotate(t, o, at, thief, thiefRoot)
	refused(t, "a rotation not signed by the recovery key (verifier)", o.ver.TakeRotation(evil.Raw))
	evilKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := *o.rootCrt
	tmpl.NotBefore = at
	primSigned, err := x509.CreateCertificate(rand.Reader, &tmpl, o.rootCrt, evilKey.Public(), o.root)
	if err != nil {
		t.Fatal(err)
	}
	refused(t, "a rotation signed by the old primary (verifier)", o.ver.TakeRotation(primSigned))
	refused(t, "a rotation signed by the old primary (issuer)", o.iss.Rotate(parse(t, primSigned), "org-2", evilKey, newKey(t), o.groups, at))

	// The owner's rotation, by the recovery key.
	oldIssuer := o.iss.Cert()
	cross, nk := rotate(t, o, at, o.rec, o.iss.Recovery())
	if err := o.iss.Rotate(cross, "org-2", nk, newKey(t), o.groups, at); err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeRotation(cross.Raw); err != nil {
		t.Fatal(err)
	}
	refused(t, "the same rotation again", o.ver.TakeRotation(cross.Raw))
	// A second rotation, then the relay replays the first.
	at2 := at.Add(time.Hour)
	cross2, nk2r := rotate(t, o, at2, o.rec, o.iss.Recovery())
	if err := o.iss.Rotate(cross2, "org-3", nk2r, newKey(t), o.groups, at2); err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeRotation(cross2.Raw); err != nil {
		t.Fatal(err)
	}
	refused(t, "a replayed older rotation", o.ver.TakeRotation(cross.Raw))
	at = at2
	o.takeCRL(t, at)
	_, err = o.ver.Check(web, oldIssuer, orgid.Peer{Name: "web-1"}, at)
	refused(t, "a certificate under the old root", err)

	// web renews into the new root with its old certificate (its serial is
	// in the log); a certificate the thief minted under the old root is not.
	nk2 := newKey(t)
	der, err := o.iss.Renew(NewRenewRequest(web.Raw, k, csr(t, nk2, "web-1")), at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ver.Check(parse(t, der), o.iss.Cert(), orgid.Peer{Name: "web-1"}, at); err != nil {
		t.Fatalf("web-1 renewed under the new root: %v", err)
	}
	mt, _ := machineTemplate(o.iss.OrgID(), "web-1", []string{"web"}, "", Device{}, o.rootCrt, t0)
	mt.SerialNumber = web.SerialNumber // serials are public
	fk := newKey(t)
	forged, err := x509.CreateCertificate(rand.Reader, mt, o.rootCrt, fk.Public(), o.root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = o.iss.Renew(NewRenewRequest(forged, fk, csr(t, newKey(t), "web-1")), at)
	refused(t, "a renewal of a certificate not in the log", err)

	if _, _, err := VerifyLog(o.lines); err != nil {
		t.Fatalf("the log after the rotation: %v", err)
	}
}

// The audit log: chained, every checkpoint signed, a rewritten line found.
func TestAuditLogChain(t *testing.T) {
	o := newOrg(t)
	o.enrol(t, "web-1", "web")
	if err := o.iss.RenewIssuer(o.root, o.groups, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	entries, head, err := VerifyLog(o.lines)
	if err != nil {
		t.Fatal(err)
	}
	if last := entries[len(entries)-1]; last.Act != ActCheckpoint || last.RootSig == nil || head != o.iss.Head() {
		t.Fatalf("last entry %+v, head %s", last, head)
	}
	// Every line but the head is chained by the one after it; the head is
	// the value a copy of the log (the owner's, a root checkpoint) holds.
	for i := range o.lines[:len(o.lines)-1] {
		bad := append([][]byte(nil), o.lines...)
		bad[i] = []byte(strings.Replace(string(bad[i]), `"time":"2026`, `"time":"2025`, 1))
		if _, _, err := VerifyLog(bad); err == nil {
			t.Fatalf("line %d rewritten: the log still verifies", i+1)
		}
	}
	// Reopened from its log, the issuer knows what it issued.
	i2, err := Open(o.lines, o.iss.key, o.sink)
	if err != nil {
		t.Fatal(err)
	}
	_, err = i2.MakeToken("web-1", []string{"web"}, "", time.Hour, t0)
	refused(t, "a token for web-1 after reopening", err)
}
