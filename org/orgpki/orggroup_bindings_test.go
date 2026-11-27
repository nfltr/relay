// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The bindings of spec/proverif/orggroup.pv (lane ONEGROUP-C1, nfltr
// docs/decisions/one-group-2026-11-25.md): the issuer applies only a move
// the root signed (BIND:group.movesig, query 5) and a peer takes a
// member's groups from the certificate the issuer signed, no other field
// (BIND:group.ou, query 3). Each row changes that field of the honest
// message and requires a refusal. BIND:group.pin is relay-server's (the
// mirror's root pin, ONEGROUP-C2). `make spec-bindings`.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

var orgGroupBindings = map[string]func(t *testing.T){
	"group.movesig": func(t *testing.T) {
		o := newOrg(t)
		c, _ := o.enrol(t, "web-1", "web")
		honest := o.moveOrder(t, "web-1", c, []string{"db"}, t0)
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		byOther, err := MoveOrder(o.pins(), other, "web-1", serialOf(c), []string{"db"}, t0)
		if err != nil {
			t.Fatal(err)
		}
		var body Order
		if err := json.Unmarshal(honest.Body, &body); err != nil {
			t.Fatal(err)
		}
		body.Groups = []string{"web", "db"}
		widened, _ := json.Marshal(body)
		for what, s := range map[string]SignedOrder{
			"another root's signature":             byOther,
			"the issuer key's signature":           {Body: honest.Body, Sig: ed25519.Sign(o.iss.key, append([]byte(orderPrefix), honest.Body...))},
			"no signature (the relay's wish)":      {Body: honest.Body},
			"the groups changed after signing":     {Body: widened, Sig: honest.Sig},
			"the root's signature of a checkpoint": {Body: honest.Body, Sig: checkpointSig(t, o)},
		} {
			if _, err := o.iss.ApplyOrder(s, t0); err == nil {
				t.Errorf("a move with %s applied", what)
			}
		}
		if _, err := o.iss.ApplyOrder(honest, t0); err != nil {
			t.Fatalf("the honest move: %v", err)
		}
	},
	"group.ou": func(t *testing.T) {
		o := newOrg(t)
		c, _ := o.enrol(t, "web-1", "web")
		o.takeCRL(t, t0)
		at := t0.Add(time.Minute)
		if _, err := o.ver.Check(c, o.iss.Cert(), orgid.Peer{Group: "web"}, at); err != nil {
			t.Fatalf("the honest certificate for web: %v", err)
		}
		// The OU changed: the same certificate with groups db, signed by
		// any key but the issuer's (the relay's, a member machine's).
		tmpl := *c
		tmpl.Subject.OrganizationalUnit = []string{"db"}
		forged := func(signer any, parent *x509.Certificate) *x509.Certificate {
			der, err := x509.CreateCertificate(rand.Reader, &tmpl, parent, c.PublicKey, signer)
			if err != nil {
				t.Fatal(err)
			}
			return parse(t, der)
		}
		dbc, mk := o.enrol(t, "db-1", "db")
		ik := newKey(t)
		asIssuer := *o.iss.Cert() // the issuer's name, another key
		asIssuer.PublicKey = ik.Public()
		for what, f := range map[string]*x509.Certificate{
			"a member machine's key": forged(mk, dbc),
			"another key as issuer":  forged(ik, &asIssuer),
		} {
			if _, err := o.ver.Check(f, o.iss.Cert(), orgid.Peer{Group: "db"}, at); err == nil {
				t.Errorf("groups db signed by %s admitted", what)
			}
		}
		// The relay's claim: the peer asks for db, the certificate says web.
		if _, err := o.ver.Check(c, o.iss.Cert(), orgid.Peer{Group: "db"}, at); err == nil {
			t.Error("a web certificate admitted for db")
		}
	},
}

// checkpointSig is the root's honest signature over a checkpoint of the
// issuer's head: a root signature that is not an order's.
func checkpointSig(t *testing.T, o *org) []byte {
	t.Helper()
	sig, err := signCheckpoint(o.root, o.iss.OrgID(), o.iss.Head())
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestOrgGroupModelBindings(t *testing.T) {
	for id, row := range orgGroupBindings {
		t.Run(id, row)
	}
}
