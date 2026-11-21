// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The issuer's signed status (status.go; spec/orgmove/OrgDash.tla,
// spec/proverif/orgdash.pv).

// It lists the members with their newest serial and the unused tokens,
// never a token's secret, and a pinned reader takes it.
func TestSignedStatusListsMembersAndTokens(t *testing.T) {
	o := newOrg(t)
	web, _ := o.enrol(t, "web-1", "web")
	tok, err := o.iss.MakeToken("db-1", []string{"db"}, "m-db-1", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.iss.Revoke("web-1", t0); err != nil {
		t.Fatal(err)
	}
	s, err := o.iss.SignedStatus(t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	st, iss, err := VerifyStatus(s, o.rootCrt)
	if err != nil {
		t.Fatal(err)
	}
	if !iss.NotAfter.Equal(o.iss.Cert().NotAfter) || st.OrgID != o.iss.OrgID() || st.Head != o.iss.Head() {
		t.Fatalf("status %+v: not the issuer's", st)
	}
	if len(st.Members) != 1 || st.Members[0].Name != "web-1" || st.Members[0].Serial != hex.EncodeToString(web.SerialNumber.Bytes()) || !st.Members[0].Revoked || st.Members[0].MachineID != "m-web-1" {
		t.Fatalf("members %+v, want web-1 revoked at serial %s", st.Members, hex.EncodeToString(web.SerialNumber.Bytes()))
	}
	if len(st.Tokens) != 1 || st.Tokens[0].Name != "db-1" || strings.Contains(string(s.Body), tok) {
		t.Fatalf("tokens %+v: want db-1's id, never the token", st.Tokens)
	}
	if st.Renewal == nil || st.Renewal.Head != st.Head {
		t.Fatalf("renewal request %+v: want one at the status's head", st.Renewal)
	}
}

const dashModel = "../../spec/proverif/orgdash.pv"

// TestOrgDashModelBindings: each BIND:dash.* of spec/proverif/orgdash.pv
// changed in the honest status, as a relay can, is refused.
func TestOrgDashModelBindings(t *testing.T) {
	src, err := os.ReadFile(dashModel)
	if err != nil {
		t.Fatal(err)
	}
	var model []string
	for _, m := range regexp.MustCompile(`BIND:(dash\.[a-z0-9.]+)`).FindAllSubmatch(src, -1) {
		model = append(model, string(m[1]))
	}
	slices.Sort(model)
	if rows := []string{"dash.notafter", "dash.ordersig", "dash.org", "dash.serial", "dash.statussig"}; !slices.Equal(model, rows) {
		t.Fatalf("%s BIND ids %v, rows %v: each binding of the model needs one row", dashModel, model, rows)
	}
	o := newOrg(t)
	o.enrol(t, "web-1", "web")
	honest, err := o.iss.SignedStatus(t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyStatus(honest, o.rootCrt); err != nil {
		t.Fatalf("honest status: %v", err)
	}
	other := newOrg(t)
	foreign, err := other.iss.SignedStatus(t0)
	if err != nil {
		t.Fatal(err)
	}
	var st Status
	if err := json.Unmarshal(honest.Body, &st); err != nil {
		t.Fatal(err)
	}
	st.Members = nil // a relay drops a member
	edited, _ := json.Marshal(st)
	for name, s := range map[string]SignedStatus{
		// BIND:dash.statussig: the body as the issuer signed it, by the key of its certificate
		"statussig: a member dropped":       {Body: edited, Sig: honest.Sig},
		"statussig: another issuer's sig":   {Body: honest.Body, Sig: foreign.Sig},
		"statussig: another organisation's": foreign,
		"statussig: no signature":           {Body: honest.Body},
	} {
		if _, _, err := VerifyStatus(s, o.rootCrt); err == nil {
			t.Errorf("%s: taken, want refused", name)
		}
	}
	// BIND:dash.notafter: days left come from the signed issuer
	// certificate; the status has no other NotAfter a relay could edit.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(honest.Body, &top); err != nil {
		t.Fatal(err)
	}
	for k := range top {
		if strings.Contains(k, "not_after") || strings.Contains(k, "days") || strings.Contains(k, "expires") {
			t.Errorf("status field %q: the issuer's NotAfter is its certificate's only", k)
		}
	}
	// The relay's own check (CheckStatusSignature) takes the foreign status:
	// it proves nothing without the pinned root.
	if _, _, err := CheckStatusSignature(foreign); err != nil {
		t.Errorf("the relay's check of a well-signed status: %v", err)
	}
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := OrgID(rk.Public())
	otherRoot, err := NewRoot(rk, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyStatus(honest, otherRoot); err == nil {
		t.Error("a status under another root: taken, want refused")
	}
	orderBindings(t)
}

// orderBindings: the revoke order's rows (order.go).
func orderBindings(t *testing.T) {
	sign := func(o *org, root crypto.Signer, ord Order) SignedOrder {
		t.Helper()
		body, err := json.Marshal(ord)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := crypto.SignMessage(root, rand.Reader, append([]byte(orderPrefix), body...), crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		return SignedOrder{Body: body, Sig: sig}
	}
	honest := func(o *org, name, serial string) Order {
		return Order{OrgID: o.iss.OrgID(), Act: ActRevokeOrder, Name: name, Serial: serial, NotAfter: t0.Add(OrderLife)}
	}
	o := newOrg(t)
	web, _ := o.enrol(t, "web-1", "web")
	db, _ := o.enrol(t, "db-1", "db")
	other := newOrg(t)
	ib, _ := json.Marshal(honest(o, "web-1", hex.EncodeToString(web.SerialNumber.Bytes())))
	byIssuer := SignedOrder{Body: ib, Sig: ed25519.Sign(o.iss.key, append([]byte(orderPrefix), ib...))}
	foreign := honest(o, "web-1", hex.EncodeToString(web.SerialNumber.Bytes()))
	foreign.OrgID = other.iss.OrgID()
	for name, s := range map[string]SignedOrder{
		// BIND:dash.ordersig: the organisation root's signature
		"ordersig: another root's":   sign(o, other.root, honest(o, "web-1", hex.EncodeToString(web.SerialNumber.Bytes()))),
		"ordersig: the issuer's key": byIssuer,
		// BIND:dash.serial: a serial of the name's current enrolment
		"serial: another member's": sign(o, o.root, honest(o, "web-1", hex.EncodeToString(db.SerialNumber.Bytes()))),
		"serial: none of it":       sign(o, o.root, honest(o, "web-1", "ff")),
		// BIND:dash.org: of this organisation
		"org: another organisation's": sign(o, o.root, foreign),
	} {
		if _, err := o.iss.ApplyOrder(s, t0); err == nil {
			t.Errorf("%s: applied, want refused", name)
		}
	}
	ok := sign(o, o.root, honest(o, "web-1", hex.EncodeToString(web.SerialNumber.Bytes())))
	if name, err := o.iss.ApplyOrder(ok, t0); err != nil || name != "web-1" {
		t.Fatalf("the honest order: %q, %v", name, err)
	}
	if _, err := o.iss.ApplyOrder(ok, t0); err == nil {
		t.Error("the same order again: applied, want refused (revoked already)")
	}
	if _, err := o.iss.ApplyOrder(ok, t0.Add(OrderLife)); err == nil {
		t.Error("a void order: applied, want refused")
	}
}
