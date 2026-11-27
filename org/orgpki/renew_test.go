// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Renewing an issuer whose root is on another machine (renew.go;
// spec/proverif/orgmove.pv queries 5-8).

var t1 = t0.Add(20 * 24 * time.Hour)

// remote is one honest round: the request at the issuer's head, the root
// holder's answer from its own copy of the log taken before the request.
func (o *org) remote(t *testing.T, at time.Time) (IssuerRenewalRequest, IssuerRenewal) {
	t.Helper()
	pins, err := ReadPins(slices.Clone(o.lines))
	if err != nil {
		t.Fatal(err)
	}
	req, err := o.iss.RenewalRequest(o.groups)
	if err != nil {
		t.Fatal(err)
	}
	ans, err := SignIssuerRenewal(pins, o.root, req, false, at)
	if err != nil {
		t.Fatal(err)
	}
	return req, ans
}

// The issuer keeps acting between its request and the answer (the hourly
// CRL); the answer checkpoints the requested head, the log verifies and
// reopens, and the same answer is not taken twice.
func TestRemoteRenewalRoundTrip(t *testing.T) {
	o := newOrg(t)
	before := o.iss.Cert().NotAfter
	_, ans := o.remote(t, t1)
	if _, err := o.iss.CRL(t1); err != nil {
		t.Fatal(err)
	}
	if err := o.iss.InstallRenewal(ans, t1); err != nil {
		t.Fatal(err)
	}
	if !o.iss.Cert().NotAfter.After(before) {
		t.Fatalf("the issuer certificate still ends %v", o.iss.Cert().NotAfter)
	}
	if _, _, err := VerifyLog(o.lines); err != nil {
		t.Fatalf("the renewed log: %v", err)
	}
	if _, err := Open(slices.Clone(o.lines), o.iss.key, o.sink); err != nil {
		t.Fatalf("the renewed log reopens: %v", err)
	}
	refused(t, "the same answer again", o.iss.InstallRenewal(ans, t1))
}

// A request for a group the pinned issuer does not have is signed only
// when the owner names the groups (widen).
func TestRemoteRenewalWidensOnlyWhenNamed(t *testing.T) {
	o := newOrg(t)
	pins, err := ReadPins(o.lines)
	if err != nil {
		t.Fatal(err)
	}
	req, err := o.iss.RenewalRequest([]string{"web", "db", "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignIssuerRenewal(pins, o.root, req, false, t1); err == nil || !strings.Contains(err.Error(), "widens") {
		t.Fatalf("a wider request: %v, want refused", err)
	}
	ans, err := SignIssuerRenewal(pins, o.root, req, true, t1)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.iss.InstallRenewal(ans, t1); err != nil {
		t.Fatal(err)
	}
	if got := o.iss.Groups(); !slices.Equal(got, []string{"db", "ops", "web"}) {
		t.Fatalf("groups %v, want %v", got, req.Groups)
	}
}

const renewModel = "../../spec/proverif/orgmove.pv"

// renewBindings: each row changes one binding of the honest round as the
// relay, the wire or another organisation can; the request then is not
// signed by the root holder, or the answer not installed.
var renewBindings = map[string]struct {
	req func(t *testing.T, o *org, r *IssuerRenewalRequest)
	ans func(t *testing.T, o *org, a *IssuerRenewal)
}{
	// A request for another key, signed by it.
	"renew.pin": {req: func(t *testing.T, _ *org, r *IssuerRenewalRequest) {
		k := newKey(t)
		r.Key = k.Public().(ed25519.PublicKey)
		r.Sig = ed25519.Sign(k, renewalMessage(*r))
	}},
	// The issuer's request with another head.
	"renew.reqsig": {req: func(_ *testing.T, _ *org, r *IssuerRenewalRequest) {
		r.Head = strings.Repeat("ab", 32)
	}},
	// Another organisation's root certifies this issuer's key.
	"renew.root": {ans: func(t *testing.T, o *org, a *IssuerRenewal) {
		ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := OrgID(ek.Public())
		er, err := NewRoot(ek, id, t0)
		if err != nil {
			t.Fatal(err)
		}
		c, err := CertifyIssuer(er, ek, o.iss.key.Public().(ed25519.PublicKey), o.groups, t1)
		if err != nil {
			t.Fatal(err)
		}
		a.Cert = c.Raw
	}},
	// The organisation's root certifies another key.
	"renew.key": {ans: func(t *testing.T, o *org, a *IssuerRenewal) {
		c, err := CertifyIssuer(o.rootCrt, o.root, newKey(t).Public().(ed25519.PublicKey), o.groups, t1)
		if err != nil {
			t.Fatal(err)
		}
		a.Cert = c.Raw
	}},
	// The root's checkpoint of a head that is not this log's.
	"renew.head": {ans: func(t *testing.T, o *org, a *IssuerRenewal) {
		a.Head = strings.Repeat("cd", 32)
		sig, err := signCheckpoint(o.root, o.iss.OrgID(), a.Head)
		if err != nil {
			t.Fatal(err)
		}
		a.RootSig = sig
	}},
}

// TestIssuerRenewalModelBindings runs every row (make spec-bindings) and
// fails when orgmove.pv's BIND:renew.* ids and the rows differ.
func TestIssuerRenewalModelBindings(t *testing.T) {
	src, err := os.ReadFile(renewModel)
	if err != nil {
		t.Fatal(err)
	}
	var model, rows []string
	for _, m := range regexp.MustCompile(`BIND:(renew\.[a-z0-9.]+)`).FindAllSubmatch(src, -1) {
		model = append(model, string(m[1]))
	}
	for id := range renewBindings {
		rows = append(rows, id)
	}
	slices.Sort(model)
	slices.Sort(rows)
	if !slices.Equal(model, rows) {
		t.Fatalf("%s BIND ids %v, rows %v: each binding of the model needs one row", renewModel, model, rows)
	}
	for _, id := range rows {
		t.Run(id, func(t *testing.T) {
			o := newOrg(t)
			pins, err := ReadPins(o.lines)
			if err != nil {
				t.Fatal(err)
			}
			req, err := o.iss.RenewalRequest(o.groups)
			if err != nil {
				t.Fatal(err)
			}
			row := renewBindings[id]
			if row.req != nil {
				row.req(t, o, &req)
				if _, err := SignIssuerRenewal(pins, o.root, req, false, t1); err == nil {
					t.Fatalf("the request with %s changed was signed; want refused", id)
				}
				return
			}
			ans, err := SignIssuerRenewal(pins, o.root, req, false, t1)
			if err != nil {
				t.Fatal(err)
			}
			row.ans(t, o, &ans)
			if err := o.iss.InstallRenewal(ans, t1); err == nil {
				t.Fatalf("the round with %s changed was installed; want refused", id)
			}
		})
	}
	// The honest round, as the rows start from it, installs.
	o := newOrg(t)
	_, ans := o.remote(t, t1)
	if err := o.iss.InstallRenewal(ans, t1); err != nil {
		t.Fatalf("the honest round: %v", err)
	}
}

// ReadPins replays every act a log may hold: a log with a sign-in rule (and
// its removal) and the people's acts reads its pins, as Open does (lane
// PEOPLE4: ReadPins built an issuer without the rules map and panicked on
// a rule line, so every root command on such a log did).
func TestReadPinsReplaysSignInRules(t *testing.T) {
	o := newOrg(t)
	r := SignInRule{ID: "idp", Issuer: "https://idp.example", ClientIDs: []string{"c1"}, App: "nfltr", Groups: []string{"web"}}
	if err := o.iss.AddSignInRule(r, t0); err != nil {
		t.Fatal(err)
	}
	_, key, err := NewInvite(o.iss.OrgID())
	if err != nil {
		t.Fatal(err)
	}
	inv, err := SignPeople(PeopleAct{OrgID: o.iss.OrgID(), Act: PeopleInvite, Person: "ana@example.com", Role: RoleMember, InviteKey: key}, o.root, nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.ApplyPeople(inv, t0); err != nil {
		t.Fatal(err)
	}
	if err := o.iss.RemoveSignInRule("idp", t0); err != nil {
		t.Fatal(err)
	}
	pins, err := ReadPins(slices.Clone(o.lines))
	if err != nil || pins.OrgID != o.iss.OrgID() {
		t.Fatalf("pins %+v, %v", pins, err)
	}
}
