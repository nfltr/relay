// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"errors"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// Moving the issuer (spec/orgmove/OrgMove.tla and its README's
// invariants). The receive keys are fingerprints here; the
// bundle that carries the log is orgissuer's.
const (
	rcpt  = "sha256:0101010101010101010101010101010101010101010101010101010101010101"
	other = "sha256:0202020202020202020202020202020202020202020202020202020202020202"
)

// moved fences o's issuer to rcpt and opens the fenced log as the new
// machine does, before its arrival.
func (o *org) moved(t *testing.T, at time.Time) (*Issuer, *[][]byte) {
	t.Helper()
	if err := o.iss.Fence(rcpt, at); err != nil {
		t.Fatal(err)
	}
	lines := append([][]byte(nil), o.lines...)
	n, err := Open(lines, o.iss.key, func(l []byte) error { lines = append(lines, l); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return n, &lines
}

// AtMostOneIssuer, OldCannotIssue (mutant serve-after-fence): after the
// fence the old issuer commits nothing, in memory or reopened, and a log
// with an act after its fence does not verify; only the arrival the fence
// names follows it.
func TestFencedIssuerRefusesEveryAct(t *testing.T) {
	o := newOrg(t)
	cert, key := o.enrol(t, "web-1", "web")
	tok, err := o.iss.MakeToken("web-2", []string{"web"}, "", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewEnrolRequest(tok, csr(t, newKey(t), "web-2"))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.iss.Fence(rcpt, t0); err != nil {
		t.Fatal(err)
	}
	fenced := len(o.lines)
	reopened, err := Open(o.lines, o.iss.key, o.sink)
	if err != nil {
		t.Fatal(err)
	}
	for _, iss := range []*Issuer{o.iss, reopened} {
		if iss.Moved() != rcpt {
			t.Fatalf("Moved() = %q, want %q", iss.Moved(), rcpt)
		}
		acts := map[string]func() error{
			"token": func() error { _, err := iss.MakeToken("web-3", []string{"web"}, "", time.Hour, t0); return err },
			"enrol": func() error { _, err := iss.Enrol(req, t0); return err },
			"renew": func() error {
				_, err := iss.Renew(NewRenewRequest(cert.Raw, key, csr(t, newKey(t), "web-1")), t0)
				return err
			},
			"revoke": func() error { return iss.Revoke("web-1", t0) },
			"crl":    func() error { _, err := iss.CRL(t0); return err },
			"issuer": func() error { return iss.RenewIssuer(o.root, o.groups, t0) },
			"fence":  func() error { return iss.Fence(other, t0) },
			"arrive": func() error { return iss.Arrive(other, t0) },
		}
		for name, act := range acts {
			if err := act(); !errors.Is(err, ErrMoved) {
				t.Errorf("%s after the fence: %v, want ErrMoved", name, err)
			}
		}
	}
	if len(o.lines) != fenced {
		t.Fatalf("the fenced log grew by %d lines", len(o.lines)-fenced)
	}
	// A log forged with an act after its fence.
	forged, err := encode(Entry{Time: t0, Act: ActRevoked, Name: "web-1"}, lineHash(o.lines[fenced-1]))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyLog(append(append([][]byte(nil), o.lines...), forged)); err == nil {
		t.Fatal("a log with an act after its fence verified")
	}
}

// AuditContinuous (mutant import-unfenced): the new machine arrives only
// on a log whose last line is a fence naming its own receive key; a
// backup, a copy before the fence, or a fence to another key is refused.
func TestMoveImportRefusesAnUnfencedCopy(t *testing.T) {
	o := newOrg(t)
	o.enrol(t, "web-1", "web")
	arrive := func(key string) error {
		lines := append([][]byte(nil), o.lines...)
		n, err := Open(lines, o.iss.key, func(l []byte) error { lines = append(lines, l); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return n.Arrive(key, t0)
	}
	if err := arrive(rcpt); err == nil || errors.Is(err, ErrMoved) {
		t.Fatalf("an unfenced copy: %v, want refused as a copy (not ErrMoved)", err)
	}
	if err := o.iss.Fence(rcpt, t0); err != nil {
		t.Fatal(err)
	}
	if err := arrive(other); err == nil {
		t.Fatal("a log fenced to another receive key was taken")
	}
	if err := arrive(rcpt); err != nil {
		t.Fatalf("the move itself: %v", err)
	}
}

// CRLMonotone: the new machine's next CRL continues the Number under the
// same issuer certificate, and the fleet's verifier takes it.
func TestMoveContinuesTheCRLNumber(t *testing.T) {
	o := newOrg(t)
	o.takeCRL(t, t0)
	n, _ := o.moved(t, t0)
	if err := n.Arrive(rcpt, t0); err != nil {
		t.Fatal(err)
	}
	if n.Cert() == nil || !n.Cert().Equal(o.iss.Cert()) {
		t.Fatal("the moved issuer's certificate changed")
	}
	der, err := n.CRL(t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if num, _ := n.LastCRL(); num != 2 {
		t.Fatalf("CRL #%d after the move, want #2", num)
	}
	if err := o.ver.TakeCRL(der, n.Cert(), t0.Add(time.Minute)); err != nil {
		t.Fatalf("the fleet refuses the moved issuer's CRL: %v", err)
	}
}

// RevokedStaysRevoked: a name revoked before the move stays revoked: no
// renewal, and its serial in the new machine's CRL.
func TestRevokedBeforeTheMoveStaysRevoked(t *testing.T) {
	o := newOrg(t)
	cert, key := o.enrol(t, "web-1", "web")
	if err := o.iss.Revoke("web-1", t0); err != nil {
		t.Fatal(err)
	}
	n, _ := o.moved(t, t0)
	if err := n.Arrive(rcpt, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Renew(NewRenewRequest(cert.Raw, key, csr(t, newKey(t), "web-1")), t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("renewal of a name revoked before the move: %v", err)
	}
	der, err := n.CRL(t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeCRL(der, n.Cert(), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ver.Check(cert, n.Cert(), orgid.Peer{}, t0); err == nil {
		t.Fatal("a certificate revoked before the move was admitted")
	}
}

// TokenOnce: a token made before the move is redeemed once, by the new
// machine; the old one refuses it.
func TestTokenRedeemedOnceAcrossTheMove(t *testing.T) {
	o := newOrg(t)
	tok, err := o.iss.MakeToken("web-1", []string{"web"}, "", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewEnrolRequest(tok, csr(t, newKey(t), "web-1"))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := o.moved(t, t0)
	if err := n.Arrive(rcpt, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.Enrol(req, t0); !errors.Is(err, ErrMoved) {
		t.Fatalf("the old machine redeemed after the fence: %v", err)
	}
	if _, err := n.Enrol(req, t0); err != nil {
		t.Fatalf("the moved issuer: %v", err)
	}
	if _, err := n.Enrol(req, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("second redemption: %v", err)
	}
}
