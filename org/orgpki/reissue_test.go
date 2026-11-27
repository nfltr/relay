// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"errors"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// Enrol.tla Rebind (same), ReissueRetiresOnlyExpired (mutant
// reissue-while-valid): the canary state of 2026-11-22 (nfltr
// docs/decisions/org-reissue-2026-11-22.md). web holds its first
// certificate and key; an answer it never took (a renewal for another key)
// superseded it; both expired. No renewal and no plain token recovers it;
// the owner's rebind token to web's own machine id does, once nothing of
// the name is valid, and is refused while something is, at its making and
// at its redemption.
func TestReissueTheCanaryState(t *testing.T) {
	o := newOrg(t)
	first, k0 := o.enrol(t, "web", "db")
	at := t0.Add(MachineLife / 2)
	k1 := newKey(t)
	untaken, err := o.iss.Renew(NewRenewRequest(first.Raw, k0, csr(t, k1, "web")), at)
	if err != nil {
		t.Fatal(err)
	}
	newest := parse(t, untaken)

	// first expired, the answer web never took still valid: no reissue.
	whileValid := first.NotAfter.Add(time.Hour)
	_, err = o.iss.Renew(NewRenewRequest(first.Raw, k0, csr(t, newKey(t), "web")), whileValid)
	refused(t, "renewing the superseded certificate", err)
	_, err = o.iss.MakeRebindToken("web", "m-web", time.Hour, whileValid)
	refused(t, "a reissue while the name holds a valid certificate", err)

	// Both expired, within the grace: the reissue to web's own id.
	stuck := newest.NotAfter.Add(time.Hour)
	_, err = o.iss.MakeToken("web", []string{"db"}, "m-web", time.Hour, stuck)
	refused(t, "a plain token for the enrolled name", err)
	tok, err := o.iss.MakeRebindToken("web", "m-web", time.Hour, stuck)
	if err != nil {
		t.Fatalf("a reissue to web's own machine id once nothing of it is valid: %v", err)
	}
	k := newKey(t)
	req, err := NewEnrolRequest(tok, csr(t, k, "web"))
	if err != nil {
		t.Fatal(err)
	}
	der, err := o.iss.Enrol(req, stuck)
	if err != nil {
		t.Fatalf("redeeming the reissue: %v", err)
	}
	got := parse(t, der)
	if got.Subject.CommonName != "web" || orgid.MachineID(got) != "m-web" {
		t.Fatalf("reissued %q at %q, want web at m-web", got.Subject.CommonName, orgid.MachineID(got))
	}
	o.takeCRL(t, stuck)
	if _, err := o.ver.Check(got, o.iss.Cert(), orgid.Peer{Group: "db"}, stuck); err != nil {
		t.Fatalf("the reissued certificate: %v", err)
	}
	_, err = o.iss.Renew(NewRenewRequest(newest.Raw, k1, csr(t, newKey(t), "web")), stuck)
	refused(t, "renewing a serial the reissue retired", err)
	if _, err := o.iss.Renew(NewRenewRequest(got.Raw, k, csr(t, newKey(t), "web")), stuck.Add(MachineLife/2)); err != nil {
		t.Fatalf("renewing the reissued certificate: %v", err)
	}
}

// A reissue token made while nothing of the name was valid is refused at
// its redemption once the name holds a valid certificate again (its
// machine came back and renewed in the grace).
func TestReissueRefusedOnceTheNameRenewed(t *testing.T) {
	o := newOrg(t)
	first, k0 := o.enrol(t, "web", "db")
	at := first.NotAfter.Add(time.Hour)
	tok, err := o.iss.MakeRebindToken("web", "m-web", time.Hour, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.Renew(NewRenewRequest(first.Raw, k0, csr(t, newKey(t), "web")), at); err != nil {
		t.Fatalf("renewing the newest in the grace: %v", err)
	}
	req, err := NewEnrolRequest(tok, csr(t, newKey(t), "web"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.Enrol(req, at); !errors.Is(err, ErrRefused) {
		t.Fatalf("a reissue redeemed while the name holds a valid certificate: %v, want refused", err)
	}
}
