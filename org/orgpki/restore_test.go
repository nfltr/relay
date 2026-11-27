// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// A restore from a backup (spec/orgmove/OrgMove.tla Revive and its
// README's restore mutants): a copy behind the published CRL serves again
// after it takes that CRL.

// lost is a backup copy of o's log taken now; o.iss then goes on as the
// lost machine's issuer.
type lost struct {
	o    *org
	copy [][]byte
}

func backup(o *org) *lost { return &lost{o: o, copy: append([][]byte(nil), o.lines...)} }

// restored opens the copy and takes crl (the newest the fleet holds) at at.
func (l *lost) restored(t *testing.T, crl []byte, at time.Time) (*Issuer, *[][]byte) {
	t.Helper()
	lines := append([][]byte(nil), l.copy...)
	n, err := Open(lines, l.o.iss.key, func(b []byte) error { lines = append(lines, append([]byte(nil), b...)); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Restore(crl, at); err != nil {
		t.Fatal(err)
	}
	return n, &lines
}

// published signs the lost issuer's CRL at at and has the fleet take it.
func (o *org) published(t *testing.T, at time.Time) []byte {
	t.Helper()
	der, err := o.iss.CRL(at)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeCRL(der, o.iss.Cert(), at); err != nil {
		t.Fatal(err)
	}
	return der
}

// CRLMonotone (mutant number-not-above-published): the restored issuer's
// next CRL is above every one the fleet took after the copy, so the fleet
// takes it; reopened, the log resumes there too.
func TestRestoreResumesAboveThePublishedCRL(t *testing.T) {
	o := newOrg(t)
	o.published(t, t0)
	l := backup(o)
	o.published(t, t0.Add(20*time.Minute))
	crl := o.published(t, t0.Add(40*time.Minute))
	at := t0.Add(3 * time.Hour)
	n, lines := l.restored(t, crl, at)
	der, err := n.CRL(at)
	if err != nil {
		t.Fatal(err)
	}
	if num, _ := n.LastCRL(); num != 4 {
		t.Fatalf("CRL #%d after a restore over #3, want #4", num)
	}
	if err := o.ver.TakeCRL(der, n.Cert(), at); err != nil {
		t.Fatalf("the fleet refuses the restored issuer's CRL: %v", err)
	}
	re, err := Open(*lines, o.iss.key, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if num, _ := re.LastCRL(); num != 4 {
		t.Fatalf("reopened: CRL #%d, want #4", num)
	}
}

// RevokedStaysRevoked (mutant merge-skipped): a name revoked after the
// copy stays revoked: its serials, the one the copy knows and the one it
// does not, are in the restored issuer's CRLs, and neither renews.
func TestRestoreKeepsThePublishedRevocations(t *testing.T) {
	o := newOrg(t)
	cert, key := o.enrol(t, "web-1", "web")
	l := backup(o)
	der, err := o.iss.Renew(NewRenewRequest(cert.Raw, key, csr(t, newKey(t), "web-1")), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	later := parse(t, der)
	if err := o.iss.Revoke("web-1", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	crl := o.published(t, t0.Add(time.Hour))
	at := t0.Add(3 * time.Hour)
	n, _ := l.restored(t, crl, at)
	for _, c := range []*struct {
		cert *[]byte
		what string
	}{{&cert.Raw, "the copy's serial"}, {&later.Raw, "a serial after the copy"}} {
		if _, err := n.Renew(NewRenewRequest(*c.cert, key, csr(t, newKey(t), "web-1")), at); !errors.Is(err, ErrRefused) {
			t.Fatalf("renewal of %s revoked after the copy: %v", c.what, err)
		}
	}
	der, err = n.CRL(at)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeCRL(der, n.Cert(), at); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*struct{ c []byte }{{cert.Raw}, {later.Raw}} {
		if _, err := o.ver.Check(parse(t, c.c), n.Cert(), orgid.Peer{}, at); err == nil {
			t.Fatal("a certificate revoked after the copy was admitted under the restored issuer's CRL")
		}
	}
}

// TokenOnce (mutant revive-keeps-tokens): a token made in the copy is void
// after the restore (the lost issuer redeemed it); a new one enrols.
func TestRestoreVoidsTheCopysTokens(t *testing.T) {
	o := newOrg(t)
	tok, err := o.iss.MakeToken("web-1", []string{"web"}, "", 3*time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	l := backup(o)
	req, err := NewEnrolRequest(tok, csr(t, newKey(t), "web-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.Enrol(req, t0); err != nil {
		t.Fatal(err)
	}
	crl := o.published(t, t0)
	at := t0.Add(2 * time.Hour)
	n, _ := l.restored(t, crl, at)
	again, err := NewEnrolRequest(tok, csr(t, newKey(t), "web-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Enrol(again, at); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "restored from a backup") {
		t.Fatalf("a token of the copy redeemed after the restore: %v", err)
	}
	fresh, err := n.MakeToken("web-2", []string{"web"}, "", time.Hour, at)
	if err != nil {
		t.Fatal(err)
	}
	if req, err = NewEnrolRequest(fresh, csr(t, newKey(t), "web-2")); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Enrol(req, at); err != nil {
		t.Fatalf("a token made after the restore: %v", err)
	}
}

// A machine that renewed after the copy renews on its own under the
// restored issuer (the certificate adopted into the log), and revoking it
// then lists the adopted serial too.
func TestRestoreAdoptsARenewalAfterTheCopy(t *testing.T) {
	o := newOrg(t)
	cert, key := o.enrol(t, "web-1", "web")
	l := backup(o)
	k2 := newKey(t)
	der, err := o.iss.Renew(NewRenewRequest(cert.Raw, key, csr(t, k2, "web-1")), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	later := parse(t, der)
	crl := o.published(t, t0.Add(time.Hour))
	at := t0.Add(3 * time.Hour)
	n, lines := l.restored(t, crl, at)
	if _, err := n.Renew(NewRenewRequest(later.Raw, k2, csr(t, newKey(t), "web-1")), at); err != nil {
		t.Fatalf("a renewal after the copy is not adopted: %v", err)
	}
	if _, err := Open(*lines, o.iss.key, func([]byte) error { return nil }); err != nil {
		t.Fatalf("the log with an adopted line: %v", err)
	}
	if err := n.Revoke("web-1", at); err != nil {
		t.Fatal(err)
	}
	if der, err = n.CRL(at); err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeCRL(der, n.Cert(), at); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ver.Check(later, n.Cert(), orgid.Peer{}, at); err == nil {
		t.Fatal("an adopted certificate stays valid after its name is revoked")
	}
}

// Adoption takes only a certificate of this issuer's key, of a name the
// log enrolled under the same relay machine id, and only after a restore.
func TestRestoreAdoptsNothingElse(t *testing.T) {
	o := newOrg(t)
	cert, key := o.enrol(t, "web-1", "web")
	l := backup(o)
	joined, jk := o.enrol(t, "web-2", "web") // joined after the copy: not in it
	crl := o.published(t, t0.Add(time.Hour))
	at := t0.Add(3 * time.Hour)
	k2 := newKey(t)
	if _, err := o.iss.Renew(NewRenewRequest(cert.Raw, key, csr(t, k2, "web-1")), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Rebound after the copy to another relay machine id: not adopted.
	rtok, err := o.iss.MakeRebindToken("web-1", "m-new", time.Hour, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	rk := newKey(t)
	rreq, err := NewEnrolRequest(rtok, csr(t, rk, "web-1"))
	if err != nil {
		t.Fatal(err)
	}
	rder, err := o.iss.Enrol(rreq, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crl = o.published(t, t0.Add(time.Hour))
	n, _ := l.restored(t, crl, at)
	if _, err := n.Renew(NewRenewRequest(rder, rk, csr(t, newKey(t), "web-1")), at); !errors.Is(err, ErrRefused) {
		t.Fatalf("a name rebound after the copy adopted: %v", err)
	}
	if _, err := n.Renew(NewRenewRequest(joined.Raw, jk, csr(t, newKey(t), "web-2")), at); !errors.Is(err, ErrRefused) {
		t.Fatalf("a name joined after the copy adopted: %v", err)
	}
	// Another issuer's certificate (another organisation) of the same name.
	p := newOrg(t)
	foreign, fk := p.enrol(t, "web-1", "web")
	if _, err := n.Renew(NewRenewRequest(foreign.Raw, fk, csr(t, newKey(t), "web-1")), at); !errors.Is(err, ErrRefused) {
		t.Fatalf("another issuer's certificate adopted: %v", err)
	}
}

// IssuerNotBehindFleet (OrgMove.tla OfferAny, mutant restore-older-crl;
// lane SECFIX2, review S8): the relay offers the restore an older CRL
// than a member holds; the restore takes the member's, so a revocation
// after the copy stays listed and the restored issuer's next CRL is one
// the fleet takes. A member CRL of another issuer is refused.
func TestRestoreTakesTheFleetsNewerCRL(t *testing.T) {
	o := newOrg(t)
	cert, key := o.enrol(t, "web-1", "web")
	l := backup(o)
	older := o.published(t, t0) // #1: what the relay hands the restore
	if err := o.iss.Revoke("web-1", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	member := o.published(t, t0.Add(time.Hour)) // #2: the fleet took it
	at := t0.Add(4 * time.Hour)
	lines := append([][]byte(nil), l.copy...)
	n, err := Open(lines, l.o.iss.key, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Restore(older, at, newOrg(t).published(t, t0)); err == nil || !strings.Contains(err.Error(), "member CRL 1 is not this issuer's") {
		t.Fatalf("a member CRL of another issuer: %v", err)
	}
	if err := n.Restore(older, at, member); err != nil {
		t.Fatal(err)
	}
	if num, _ := n.LastCRL(); num != 2 {
		t.Fatalf("restored at CRL #%d: below the fleet's #2", num)
	}
	der, err := n.CRL(at)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeCRL(der, n.Cert(), at); err != nil {
		t.Fatalf("the fleet refuses the restored issuer's CRL: %v", err)
	}
	if _, err := o.ver.Check(cert, n.Cert(), orgid.Peer{}, at); err == nil {
		t.Fatal("a machine revoked after the copy is admitted under the restored issuer")
	}
	if _, err := n.Renew(NewRenewRequest(cert.Raw, key, csr(t, newKey(t), "web-1")), at); !errors.Is(err, ErrRefused) {
		t.Fatalf("a machine revoked after the copy renews: %v", err)
	}
}

// Restore refuses a CRL signed less than RestoreQuiet ago (an issuer may
// still publish; a restore no longer waits for its day-long lapse), one
// older than the copy's own (not the newest), another issuer's, and a
// fenced copy; and without a restore a certificate the log lacks is not
// adopted.
func TestRestoreRefusals(t *testing.T) {
	o := newOrg(t)
	cert, _ := o.enrol(t, "web-1", "web")
	older := o.published(t, t0)
	crl := o.published(t, t0)
	l := backup(o)
	n, err := Open(append([][]byte(nil), l.copy...), o.iss.key, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Restore(crl, t0.Add(30*time.Minute)); !errors.Is(err, ErrNotQuiet) {
		t.Fatalf("a restore over a CRL signed less than RestoreQuiet ago: %v", err)
	}
	if err := n.Restore(older, t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "not the newest") {
		t.Fatalf("a restore over a CRL older than the copy's own: %v", err)
	}
	p := newOrg(t)
	if err := n.Restore(p.published(t, t0), t0.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "not this issuer's") {
		t.Fatalf("a restore over another issuer's CRL: %v", err)
	}
	// A certificate of the issuer's key the log lacks (as the lost machine
	// would have issued it), with no restore in the log.
	k := newKey(t)
	tmpl, err := machineTemplate(o.iss.orgID, "web-1", []string{"web"}, orgid.MachineID(cert), Device{}, o.iss.cert, t0)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, o.iss.cert, k.Public(), o.iss.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Renew(NewRenewRequest(der, k, csr(t, newKey(t), "web-1")), t0.Add(time.Hour)); !errors.Is(err, ErrRefused) {
		t.Fatalf("a certificate not in the log adopted with no restore: %v", err)
	}
	if err := n.Fence(rcpt, t0); err != nil {
		t.Fatal(err)
	}
	if err := n.Restore(crl, t0.Add(2*time.Hour)); !errors.Is(err, ErrMoved) {
		t.Fatalf("a restore after the fence: %v", err)
	}
}
