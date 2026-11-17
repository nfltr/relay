// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// rebindReq is the new machine's request under a rebind token.
func rebindReq(t *testing.T, o *org, name, machineID string) (EnrolRequest, ed25519.PrivateKey) {
	t.Helper()
	tok, err := o.iss.MakeRebindToken(name, machineID, 2*time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	req, err := NewEnrolRequest(tok, csr(t, k, name))
	if err != nil {
		t.Fatal(err)
	}
	return req, k
}

// Enrol.tla Rebind, RetiredRefused, NoRenewOfRetired: the name keeps its
// groups under the new machine id; every earlier serial is in the next CRL
// and renews no more (mutants rebind-keeps-serials, renew-rebound); the
// rebound certificate is admitted and renews.
func TestRebindRetiresTheOldID(t *testing.T) {
	o := newOrg(t)
	first, k := o.enrol(t, "web", "db")
	at := t0.Add(time.Hour)
	k2 := newKey(t)
	der, err := o.iss.Renew(NewRenewRequest(first.Raw, k, csr(t, k2, "web")), at)
	if err != nil {
		t.Fatal(err)
	}
	second := parse(t, der)
	req, nk := rebindReq(t, o, "web", mid)
	der, err = o.iss.Enrol(req, at)
	if err != nil {
		t.Fatal(err)
	}
	moved := parse(t, der)
	if got := orgid.MachineID(moved); got != mid {
		t.Fatalf("rebound machine id %q, want %q", got, mid)
	}
	if !slices.Equal(moved.Subject.OrganizationalUnit, []string{"db"}) {
		t.Fatalf("rebound groups %v, want [db]", moved.Subject.OrganizationalUnit)
	}
	if !o.iss.CRLDue() {
		t.Fatal("no CRL due after the rebind")
	}
	if got := o.iss.NameOfMachine(mid); got != "web" {
		t.Fatalf("NameOfMachine(new id) = %q, want web", got)
	}
	if got := o.iss.NameOfMachine("m-web"); got != "" {
		t.Fatalf("NameOfMachine(old id) = %q, want none", got)
	}
	o.takeCRL(t, at)
	for name, c := range map[string]*x509.Certificate{"the old id's renewed certificate": second, "the old id's first certificate": first} {
		_, err := o.ver.Check(c, o.iss.Cert(), orgid.Peer{Group: "db"}, at)
		refused(t, name, err)
	}
	if _, err := o.ver.Check(moved, o.iss.Cert(), orgid.Peer{Group: "db"}, at); err != nil {
		t.Fatalf("the rebound certificate: %v", err)
	}
	_, err = o.iss.Renew(NewRenewRequest(second.Raw, k2, csr(t, newKey(t), "web")), at)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("renewal of the old id's certificate: %v, want refused", err)
	}
	if _, err := o.iss.HostCert(second.Raw, at); !errors.Is(err, ErrRefused) {
		t.Fatalf("host certificate of the old id's certificate: %v, want refused", err)
	}
	der, err = o.iss.Renew(NewRenewRequest(moved.Raw, nk, csr(t, newKey(t), "web")), at)
	if err != nil {
		t.Fatalf("renewal of the rebound certificate: %v", err)
	}
	if got := orgid.MachineID(parse(t, der)); got != mid {
		t.Fatalf("renewed machine id %q, want %q", got, mid)
	}
	// The log replays to the same state.
	again, err := Open(o.lines, o.iss.key, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if again.names["web"].retired != 2 || again.names["web"].machineID != mid {
		t.Fatalf("replayed log: retired %d, machine id %q", again.names["web"].retired, again.names["web"].machineID)
	}
}

// enrol.pv query 11 (a rebind token rebinds only the enrolled name it was
// made for) and MakeToken's rules: a rebind token only for an enrolled,
// unrevoked name and another id; a plain token never for an enrolled one;
// the certificate names the token's name, not the request's; single use,
// answered again only for the key it rebound.
func TestRebindTokenRules(t *testing.T) {
	o := newOrg(t)
	o.enrol(t, "web", "db")
	o.enrol(t, "lost", "db")
	if err := o.iss.Revoke("lost", t0); err != nil {
		t.Fatal(err)
	}
	for what, err := range map[string]error{
		"an unknown name": func() error { _, err := o.iss.MakeRebindToken("new1", mid, time.Hour, t0); return err }(),
		"a revoked name":  func() error { _, err := o.iss.MakeRebindToken("lost", mid, time.Hour, t0); return err }(),
		"the same id":     func() error { _, err := o.iss.MakeRebindToken("web", "m-web", time.Hour, t0); return err }(),
		"no id":           func() error { _, err := o.iss.MakeRebindToken("web", "", time.Hour, t0); return err }(),
		"a plain token for an enrolled name": func() error {
			_, err := o.iss.MakeToken("web", []string{"db"}, mid, time.Hour, t0)
			return err
		}(),
	} {
		refused(t, what, err)
	}
	// The request names another name: the certificate is the token's.
	o.enrol(t, "other", "web")
	tok, err := o.iss.MakeRebindToken("web", mid, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	req, _ := NewEnrolRequest(tok, csr(t, k, "other"))
	der, err := o.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	if cn := parse(t, der).Subject.CommonName; cn != "web" {
		t.Fatalf("rebound name %q, want the token's (web)", cn)
	}
	// Answered again for its key (a lost answer), never for another.
	if _, err := o.iss.Enrol(req, t0); err != nil {
		t.Fatalf("the same key again: %v", err)
	}
	if o.iss.names["web"].retired != 1 {
		t.Fatalf("an answer again retired %d serials, want 1: it retires only what came before the rebind", o.iss.names["web"].retired)
	}
	req2, _ := NewEnrolRequest(tok, csr(t, newKey(t), "web"))
	if _, err := o.iss.Enrol(req2, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("the rebind token for another key: %v, want refused", err)
	}
}
