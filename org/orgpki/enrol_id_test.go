// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"errors"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// A login bundle's token names no relay machine id (spec/enrol/Join.tla,
// lane LOGINREDS): the join states its own under the token's MAC and the
// issuer binds it when the move policy admits it (JoinedBound), so the
// keeper of the machine's first serve moves nothing; a policy that
// refuses, or none, leaves the certificate without an id, as before
// (BindOnlyOwnAccount).
func TestEnrolBindsTheStatedMachineID(t *testing.T) {
	for _, c := range []struct {
		name   string
		policy MovePolicy
		want   string
	}{
		{"admitted", func(name, id string) error { return nil }, mid},
		{"refused", func(name, id string) error { return errors.New("not the account's machine box") }, ""},
		{"no policy", nil, ""},
	} {
		o := newOrg(t)
		o.iss.SetMovePolicy(c.policy)
		tok, err := o.iss.MakeToken("box", []string{"web"}, "", time.Hour, t0)
		if err != nil {
			t.Fatal(err)
		}
		k := newKey(t)
		req, err := NewEnrolRequestFor(tok, csr(t, k, "box"), mid)
		if err != nil {
			t.Fatal(err)
		}
		der, err := o.iss.Enrol(req, t0)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := orgid.MachineID(parse(t, der)); got != c.want {
			t.Fatalf("%s: machine id %q, want %q", c.name, got, c.want)
		}
		// Asked again for the same key (a lost answer): the same binding.
		if der, err = o.iss.Enrol(req, t0); err != nil || orgid.MachineID(parse(t, der)) != c.want {
			t.Fatalf("%s: answered again: %v", c.name, err)
		}
	}
}

// A token that names a machine id keeps it: the request's id binds only
// where the token names none.
func TestEnrolTokenMachineIDWins(t *testing.T) {
	o := newOrg(t)
	o.iss.SetMovePolicy(func(string, string) error { return nil })
	tok, err := o.iss.MakeToken("box", []string{"web"}, "m-bbbbbbbbbbbbbbbbbbbbbbbbbb", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewEnrolRequestFor(tok, csr(t, newKey(t), "box"), mid)
	if err != nil {
		t.Fatal(err)
	}
	der, err := o.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	if got := orgid.MachineID(parse(t, der)); got != "m-bbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("machine id %q, want the token's", got)
	}
}

// BIND:enrol.id (Join.tla Relabel, mutant bind-unmacd): the relay changes
// the id of the honest request it carries, or adds one; refused, the id is
// under the token's MAC, and the token stays unredeemed.
func TestEnrolIDModelBindings(t *testing.T) {
	for b, change := range map[string]func(*EnrolRequest){
		"enrol.id":       func(r *EnrolRequest) { r.MachineID = "m-cccccccccccccccccccccccccc" },
		"enrol.id added": func(r *EnrolRequest) { r.MachineID, r.MachineMAC = "m-cccccccccccccccccccccccccc", nil },
	} {
		o := newOrg(t)
		o.iss.SetMovePolicy(func(string, string) error { return nil }) // the relay's word only
		tok, err := o.iss.MakeToken("box", []string{"web"}, "", time.Hour, t0)
		if err != nil {
			t.Fatal(err)
		}
		id := mid
		if b == "enrol.id added" {
			id = ""
		}
		k := newKey(t)
		req, err := NewEnrolRequestFor(tok, csr(t, k, "box"), id)
		if err != nil {
			t.Fatal(err)
		}
		change(&req)
		if _, err := o.iss.Enrol(req, t0); !errors.Is(err, ErrRefused) {
			t.Fatalf("BIND:%s changed: %v, want refused", b, err)
		}
		if got := o.iss.NameOfMachine("m-cccccccccccccccccccccccccc"); got != "" {
			t.Fatalf("BIND:%s: NameOfMachine = %q: the relay chose the id", b, got)
		}
		honest, err := NewEnrolRequestFor(tok, csr(t, k, "box"), mid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := o.iss.Enrol(honest, t0); err != nil {
			t.Fatalf("BIND:%s: the honest request after the refusal: %v (the token was spent)", b, err)
		}
	}
}
