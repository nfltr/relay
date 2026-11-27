// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// An app's device enrolled for a person by an admin code (nfltr
// docs/decisions/app-device-identity-2026-11-16.md; spec/appenrol/AppEnrol.tla,
// spec/proverif/app_enrol.pv): the token names the person and the app,
// the certificate carries them, a renewal keeps them, and revoking a
// person or an app revokes every name of it and refuses its enrolments.

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

func (o *org) device(t *testing.T, name, person, app string) (*x509.Certificate, string) {
	t.Helper()
	tok, err := o.iss.MakeDeviceToken(name, []string{"web"}, "m-"+name, Device{Person: person, App: app}, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	req, err := NewEnrolRequest(tok, csr(t, k, name))
	if err != nil {
		t.Fatal(err)
	}
	der, err := o.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, der), name
}

func appURI(c *x509.Certificate) string {
	for _, u := range c.URIs {
		if u.Scheme == "nfltr" && len(u.Path) > len(appURIPath) && u.Path[:len(appURIPath)] == appURIPath {
			return u.Path[len(appURIPath):]
		}
	}
	return ""
}

// AppEnrol.tla AttrsFixed (mutant renew-takes-attrs): the person and app
// of the code, in the certificate and in every renewal.
func TestDeviceTokenNamesPersonAndApp(t *testing.T) {
	o := newOrg(t)
	tok, err := o.iss.MakeDeviceToken("send-1", []string{"web"}, "m-send-1", Device{Person: "Alice@Example.com", App: "send"}, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	req, err := NewEnrolRequest(tok, csr(t, k, "send-1"))
	if err != nil {
		t.Fatal(err)
	}
	der, err := o.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	c := parse(t, der)
	if !slices.Equal(c.EmailAddresses, []string{"alice@example.com"}) || appURI(c) != "send" {
		t.Fatalf("certificate person %v app %q", c.EmailAddresses, appURI(c))
	}
	k2 := newKey(t)
	at := t0.Add(MachineLife / 2)
	rd, err := o.iss.Renew(NewRenewRequest(der, k, csr(t, k2, "send-1")), at)
	if err != nil {
		t.Fatal(err)
	}
	r := parse(t, rd)
	if !slices.Equal(r.EmailAddresses, []string{"alice@example.com"}) || appURI(r) != "send" {
		t.Fatalf("renewed person %v app %q", r.EmailAddresses, appURI(r))
	}
	// A plain machine's token names neither.
	web, _ := o.enrol(t, "web-1", "web")
	if len(web.EmailAddresses) != 0 || appURI(web) != "" {
		t.Fatalf("plain machine: person %v app %q", web.EmailAddresses, appURI(web))
	}
	for _, d := range []Device{{Person: "not an address"}, {App: "Bad App"}, {Person: "Alice <alice@example.com>"}} {
		if _, err := o.iss.MakeDeviceToken("send-9", []string{"web"}, "", d, time.Hour, t0); err == nil {
			t.Errorf("device %+v: accepted", d)
		}
	}
}

// AppEnrol.tla RevokedUserCut (mutants revoke-user-one-name,
// sso-skips-deny): every name of the person in the next CRL, its renewals
// and a code made before the revoke refused, no new code for it.
func TestRevokePersonRevokesEveryName(t *testing.T) {
	o := newOrg(t)
	a1, _ := o.device(t, "send-1", "alice@example.com", "send")
	a2, _ := o.device(t, "desk-1", "alice@example.com", "desk")
	b1, _ := o.device(t, "send-2", "bob@example.com", "send")
	early, err := o.iss.MakeDeviceToken("send-3", []string{"web"}, "", Device{Person: "alice@example.com", App: "send"}, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.RevokePerson("alice@example.com", t0); err != nil {
		t.Fatal(err)
	}
	o.takeCRL(t, t0.Add(time.Minute))
	at := t0.Add(2 * time.Minute)
	for _, c := range []*x509.Certificate{a1, a2} {
		if _, err := o.ver.Check(c, o.iss.Cert(), orgid.Peer{Group: "web"}, at); err == nil {
			t.Errorf("%s: admitted after alice was revoked", c.Subject.CommonName)
		}
	}
	if _, err := o.ver.Check(b1, o.iss.Cert(), orgid.Peer{Group: "web"}, at); err != nil {
		t.Errorf("bob's send-2: %v", err)
	}
	k := newKey(t)
	req, err := NewEnrolRequest(early, csr(t, k, "send-3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.Enrol(req, at); !errors.Is(err, ErrRefused) {
		t.Errorf("a code made before the revoke: %v, want refused", err)
	}
	if _, err := o.iss.MakeDeviceToken("send-4", []string{"web"}, "", Device{Person: "alice@example.com", App: "send"}, time.Hour, at); err == nil {
		t.Error("a new code for a revoked person: made")
	}
}

// AppEnrol.tla RevokedAppCut (mutant revoke-app-sso-only): every name of
// the app, whoever holds it.
func TestRevokeAppRevokesEveryName(t *testing.T) {
	o := newOrg(t)
	s1, _ := o.device(t, "send-1", "alice@example.com", "send")
	s2, _ := o.device(t, "send-2", "bob@example.com", "send")
	d1, _ := o.device(t, "desk-1", "alice@example.com", "desk")
	if err := o.iss.RevokeApp("send", t0); err != nil {
		t.Fatal(err)
	}
	o.takeCRL(t, t0.Add(time.Minute))
	at := t0.Add(2 * time.Minute)
	for _, c := range []*x509.Certificate{s1, s2} {
		if _, err := o.ver.Check(c, o.iss.Cert(), orgid.Peer{Group: "web"}, at); err == nil {
			t.Errorf("%s: admitted after send was revoked", c.Subject.CommonName)
		}
	}
	if _, err := o.ver.Check(d1, o.iss.Cert(), orgid.Peer{Group: "web"}, at); err != nil {
		t.Errorf("alice's desk-1: %v", err)
	}
	if _, err := o.iss.MakeDeviceToken("send-5", []string{"web"}, "", Device{Person: "carol@example.com", App: "send"}, time.Hour, at); err == nil {
		t.Error("a new code for a revoked app: made")
	}
}

// Finding F1: the issuer's certificate constrains URI SANs to the
// organisation's domain, so a leaf with an app or machine URI of another
// organisation does not chain (crypto/x509 checks URIs against
// PermittedURIDomains only).
func TestIssuerConstrainsURIs(t *testing.T) {
	o := newOrg(t)
	tmpl, err := machineTemplate(o.iss.OrgID(), "send-1", []string{"web"}, "", Device{}, o.iss.Cert(), t0)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.URIs = []*url.URL{{Scheme: "nfltr", Host: "o-elsewhere.internal", Path: appURIPath + "send"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, o.iss.Cert(), newKey(t).Public(), o.iss.key)
	if err != nil {
		t.Fatal(err)
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(o.rootCrt)
	inter.AddCert(o.iss.Cert())
	if _, err := parse(t, der).Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: t0, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		t.Fatal("a URI SAN of another organisation chains")
	}
}
