// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The grants' bindings of spec/proverif/svc_access.pv (lane SA4, nfltr
// docs/decisions/service-access-2026-11-25.md "Grants"): the agent admits
// by a grant only under the issuer's key (BIND:svc.grantsig, query 1),
// naming the session's certified principal (BIND:svc.grantwho) and the
// service it opened (BIND:svc.grantsvc); the issuer signs one only for an
// approval over the whole request (BIND:svc.apprall, query 2). Each row
// changes one field of the honest message and requires a refusal. The SA3
// rows are client/orgid's. `make spec-bindings`.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// granted is bob's honest grant of crm/web, the CRL taken at at.
func granted(t *testing.T) (*grantOrg, *x509.Certificate, time.Time) {
	t.Helper()
	o := newGrantOrg(t)
	at := t0.Add(time.Minute)
	r := o.ask(t, "req-00000001", time.Hour, at)
	a, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at)
	if err != nil {
		t.Fatal(err)
	}
	g := o.grantCert(t, a.Serial, at)
	o.takeCRL(t, at)
	if _, err := o.admit(t, o.bob, g, "web", at); err != nil {
		t.Fatalf("the honest grant: %v", err)
	}
	return o, g, at
}

// reissue is g as signer signs it after change (the relay's or an
// insider's own grant).
func reissue(t *testing.T, g *x509.Certificate, parent *x509.Certificate, signer any, change func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: sn, NotBefore: g.NotBefore, NotAfter: g.NotAfter, BasicConstraintsValid: true,
		ExtKeyUsage: g.ExtKeyUsage, URIs: []*url.URL{{Scheme: g.URIs[0].Scheme, Host: g.URIs[0].Host, Path: g.URIs[0].Path, RawQuery: g.URIs[0].RawQuery}}}
	if change != nil {
		change(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, g.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, der)
}

func withQuery(key, value string) func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		q := c.URIs[0].Query()
		q.Set(key, value)
		c.URIs[0].RawQuery = q.Encode()
	}
}

var grantBindings = map[string]func(t *testing.T){
	"svc.grantsig": func(t *testing.T) {
		o, g, at := granted(t)
		other := newGrantOrg(t)
		for what, c := range map[string]*x509.Certificate{
			"another organisation's issuer":   reissue(t, g, other.iss.Cert(), other.iss.key, nil),
			"a member machine's key (crm's)":  reissue(t, g, o.crm.cert, o.crm.key, nil),
			"the issuer's, for another org":   reissue(t, g, o.iss.Cert(), o.iss.key, func(c *x509.Certificate) { c.URIs[0].Host = orgid.Domain(other.iss.OrgID()) }),
			"the issuer's, past its own life": reissue(t, g, o.iss.Cert(), o.iss.key, func(c *x509.Certificate) { c.NotAfter = at }),
		} {
			if _, err := o.admit(t, o.bob, c, "web", at); err == nil {
				t.Errorf("a grant signed by %s admitted", what)
			}
		}
	},
	"svc.grantwho": func(t *testing.T) {
		o, g, at := granted(t)
		if _, err := o.admit(t, o.carol, g, "web", at); err == nil {
			t.Error("bob's grant admitted carol's machine")
		}
		// The issuer's own signature, naming another principal than the
		// key's certificate: the principal must be the session's.
		for _, who := range []string{"person:carol@acme.com", "machine:bob-mac", "group:web"} {
			if _, err := o.admit(t, o.bob, reissue(t, g, o.iss.Cert(), o.iss.key, withQuery("who", who)), "web", at); err == nil {
				t.Errorf("a grant for %s admitted bob", who)
			}
		}
	},
	"svc.grantsvc": func(t *testing.T) {
		o, g, at := granted(t)
		if _, err := o.admit(t, o.bob, g, "ssh", at); err == nil {
			t.Error("a grant for web admitted ssh")
		}
		for what, c := range map[string]*x509.Certificate{
			"another place":   reissue(t, g, o.iss.Cert(), o.iss.key, withQuery("where", "machine:db-1")),
			"a group crm":     reissue(t, g, o.iss.Cert(), o.iss.key, withQuery("where", "group:crm")),
			"every service":   reissue(t, g, o.iss.Cert(), o.iss.key, withQuery("service", "*")),
			"another service": reissue(t, g, o.iss.Cert(), o.iss.key, withQuery("service", "ssh")),
		} {
			if _, err := o.admit(t, o.bob, c, "web", at); err == nil {
				t.Errorf("a grant for %s admitted crm/web", what)
			}
		}
	},
	"svc.apprall": func(t *testing.T) {
		o := newGrantOrg(t)
		at := t0.Add(time.Minute)
		ask := GrantAct{OrgID: o.iss.OrgID(), Act: GrantAsk, ID: "req-00000001", Where: "machine:crm", Service: "web", ForS: 3600, Reason: "INC-1"}
		honest, err := SignGrant(ask, o.bob.key, o.bob.cert.Raw, at)
		check(t, err)
		if _, err := o.iss.ApplyGrant(honest, at); err != nil {
			t.Fatal(err)
		}
		// alice approved another body under the same id (a relay's or bob's
		// longer, wider or other request): the issuer holds bob's, and
		// takes an approval only over it.
		for what, change := range map[string]func(*GrantAct){
			"a longer duration": func(a *GrantAct) { a.ForS *= 24 },
			"another service":   func(a *GrantAct) { a.Service = "ssh" },
			"another place":     func(a *GrantAct) { a.Where = "group:db" },
			"another reason":    func(a *GrantAct) { a.Reason = "" },
		} {
			other := ask
			change(&other)
			r, err := SignGrant(other, o.bob.key, o.bob.cert.Raw, at)
			check(t, err)
			if _, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: ask.ID, Digest: digestOf(r.Body)}, at); err == nil {
				t.Errorf("an approval of %s taken", what)
			}
		}
		if _, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: ask.ID}, at); err == nil {
			t.Error("an approval over no body taken")
		}
		if _, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: ask.ID, Digest: digestOf(honest.Body)}, at); err != nil {
			t.Errorf("the honest approval: %v", err)
		}
	},
}

// TestSvcAccessModelBindingsGrants runs every row; each is a BIND id of
// the model, the SA4 ones.
func TestSvcAccessModelBindingsGrants(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/svc_access.pv")
	if err != nil {
		t.Fatal(err)
	}
	for id, row := range grantBindings {
		if !strings.Contains(string(src), "BIND:"+id+" ") {
			t.Errorf("svc_access.pv declares no BIND:%s", id)
		}
		t.Run(id, row)
	}
}

func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
