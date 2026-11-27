// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"bytes"
	"crypto/x509"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// The same rows as client/orgid's shortNameCases (validShort is a copy of
// orgid.ValidShortName; "" is none here, so valid).
func TestValidShortName(t *testing.T) {
	for s, want := range map[string]bool{
		"acme": true, "a": true, "acme-corp": true, "a1": true, strings.Repeat("a", 63): true, "": true,
		"o-x": false, "o-": false, "Acme": false, "1acme": false, "-acme": false,
		"acme-": false, "ac_me": false, "ac.me": false, strings.Repeat("a", 64): false,
	} {
		if got := validShort(s) == nil; got != want {
			t.Errorf("validShort(%q) ok = %v, want %v", s, got, want)
		}
	}
}

// names are a root's name URI SANs.
func names(c *x509.Certificate) []string {
	var n []string
	for _, u := range c.URIs {
		if s, ok := strings.CutPrefix(u.Path, nameURIPath); ok && u.Scheme == "nfltr" {
			n = append(n, u.Host+" "+s)
		}
	}
	return n
}

func TestNewRootShortName(t *testing.T) {
	o := newOrg(t)
	id := o.iss.OrgID()
	for short, want := range map[string][]string{"": nil, "acme": {orgid.Domain(id) + " acme"}} {
		r, err := NewRoot(o.root, id, t0, WithShortName(short))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names(r), want) || !bytes.Equal(r.RawSubject, o.rootCrt.RawSubject) {
			t.Errorf("short %q: names %q, Subject %q", short, names(r), r.Subject)
		}
		if got, _ := orgid.OrgIDOfRoot(r); got != id {
			t.Errorf("short %q: org id %q, want %q", short, got, id)
		}
	}
	// No option: an unnamed root, as before SA1, for a root and a rotation.
	if r, err := NewRoot(o.root, id, t0); err != nil || names(r) != nil {
		t.Errorf("NewRoot without WithShortName: names %q, err %v", names(r), err)
	}
	if c, err := CrossSign(o.iss.Recovery(), o.rec, newKey(t).Public(), id, t0); err != nil || names(c) != nil {
		t.Errorf("CrossSign without WithShortName: names %q, err %v", names(c), err)
	}
	if _, err := NewRoot(o.root, id, t0, WithShortName("o-acme")); err == nil {
		t.Error("NewRoot took the short name o-acme")
	}
	if _, err := CrossSign(o.iss.Recovery(), o.rec, o.root.Public(), id, t0, WithShortName("Acme")); err == nil {
		t.Error("CrossSign took the short name Acme")
	}
}

// A rotation carries the short name, and verifiers take it.
func TestCrossSignKeepsShortName(t *testing.T) {
	o := newOrg(t)
	at := t0.Add(time.Hour)
	nk := newKey(t)
	cross, err := CrossSign(o.iss.Recovery(), o.rec, nk.Public(), o.iss.OrgID(), at, WithShortName("acme"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names(cross), []string{orgid.Domain(o.iss.OrgID()) + " acme"}) {
		t.Fatalf("names %q", names(cross))
	}
	if err := o.ver.TakeRotation(cross.Raw); err != nil {
		t.Fatal(err)
	}
}

// A re-sign (the same root key, now with a short name) keeps the pin, the
// id and the Subject: the existing issuer certificate and a machine's
// under it check, with no issuer certified again.
func TestResignedRootKeepsChains(t *testing.T) {
	o := newOrg(t)
	web, _ := o.enrol(t, "web-1", "web")
	re, err := NewRoot(o.root, o.iss.OrgID(), t0, WithShortName("acme"))
	if err != nil {
		t.Fatal(err)
	}
	rec := o.iss.Recovery()
	v, err := orgid.NewVerifier(re, rec, orgid.Fingerprint(o.rootCrt), orgid.Fingerprint(rec))
	if err != nil {
		t.Fatalf("the re-signed root is not the pinned one: %v", err)
	}
	crl, err := o.iss.CRL(t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.TakeCRL(crl, o.iss.Cert(), t0); err != nil {
		t.Fatalf("the existing issuer under the re-signed root: %v", err)
	}
	if _, err := v.Check(web, o.iss.Cert(), orgid.Peer{Name: "web-1"}, t0); err != nil {
		t.Fatalf("the machine under the re-signed root: %v", err)
	}
}
