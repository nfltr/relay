// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"errors"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// ownAccount is a move policy admitting only web to mid (the issuer's
// account's machine of that name).
func ownAccount(name, id string) error {
	if name == "web" && id == mid {
		return nil
	}
	return errors.New("not a machine of this account by that name")
}

// Enrol.tla Move: the name's machine enrolled with the relay again (a new
// relay machine id) and asks with its key, its certificate expired 20 days
// ago (inside RenewGrace): the name moves to the new id, its earlier serials
// retired, with no rebind token.
func TestRenewalMovesTheNameToItsNewRelayID(t *testing.T) {
	o := newOrg(t)
	first, k := o.enrol(t, "web", "db")
	o.iss.SetMovePolicy(ownAccount)
	at := first.NotAfter.Add(20 * 24 * time.Hour) // past the old week of grace; inside the issuer's 30 days
	der, err := o.iss.Renew(NewMoveRequest(first.Raw, k, csr(t, newKey(t), "web"), mid), at)
	if err != nil {
		t.Fatal(err)
	}
	if got := orgid.MachineID(parse(t, der)); got != mid {
		t.Fatalf("moved machine id %q, want %q", got, mid)
	}
	if got := o.iss.NameOfMachine(mid); got != "web" {
		t.Fatalf("NameOfMachine(new id) = %q, want web", got)
	}
	if !o.iss.CRLDue() {
		t.Fatal("no CRL due after the move: the old id's serials are not listed")
	}
	if _, err := o.iss.Renew(NewRenewRequest(first.Raw, k, csr(t, newKey(t), "web")), at); !errors.Is(err, ErrRefused) {
		t.Fatalf("the old id's certificate after the move: %v, want refused (retired)", err)
	}
}

// Enrol.tla MoveOnlyOwnAccount (mutant move-any-account), the default: an
// id the policy refuses (another account's machine), or no policy, moves
// nothing; the name keeps renewing under its id.
func TestMoveRefusedOutsideThePolicy(t *testing.T) {
	o := newOrg(t)
	first, k := o.enrol(t, "web", "db")
	at := t0.Add(20 * time.Hour)
	if _, err := o.iss.Renew(NewMoveRequest(first.Raw, k, csr(t, newKey(t), "web"), mid), at); !errors.Is(err, ErrRefused) {
		t.Fatalf("a move with no policy: %v, want refused", err)
	}
	o.iss.SetMovePolicy(ownAccount)
	other := "m-bbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := o.iss.Renew(NewMoveRequest(first.Raw, k, csr(t, newKey(t), "web"), other), at); !errors.Is(err, ErrRefused) {
		t.Fatalf("a move to another account's machine: %v, want refused", err)
	}
	if got := o.iss.NameOfMachine(other); got != "" {
		t.Fatalf("NameOfMachine(other) = %q after a refused move", got)
	}
	der, err := o.iss.Renew(NewRenewRequest(first.Raw, k, csr(t, newKey(t), "web")), at)
	if err != nil {
		t.Fatalf("a plain renewal after the refused moves: %v", err)
	}
	if got := orgid.MachineID(parse(t, der)); got != "m-web" {
		t.Fatalf("renewed machine id %q, want m-web", got)
	}
}

// enrol.pv query 20, BIND:move.id: the relay carrying the honest move
// request changes its machine id (to one the policy admits): refused, the
// id is under the key's signature (mutant move-id-unsigned).
func TestMoveModelBindings(t *testing.T) {
	o := newOrg(t)
	first, k := o.enrol(t, "web", "db")
	o.iss.SetMovePolicy(func(string, string) error { return nil }) // the relay's word only
	req := NewMoveRequest(first.Raw, k, csr(t, newKey(t), "web"), "m-cccccccccccccccccccccccccc")
	req.MachineID = mid // BIND:move.id
	if _, err := o.iss.Renew(req, t0.Add(20*time.Hour)); !errors.Is(err, ErrRefused) {
		t.Fatalf("a move whose id the relay changed: %v, want refused", err)
	}
	if got := o.iss.NameOfMachine(mid); got != "" {
		t.Fatalf("NameOfMachine(%s) = %q: the relay chose the id", mid, got)
	}
}
