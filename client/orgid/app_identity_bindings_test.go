// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

// The device certificate's bindings of spec/proverif/app_enrol.pv: a
// service admitting persons and apps (allow_user, allow_app) takes a
// device certificate of those only (BIND:app.attrs; mutant no-app-check),
// and an nfltr URI SAN must name the organisation, which the issuer's DNS
// name constraints do not check (BIND:app.urihost; finding F1 of nfltr
// docs/decisions/app-device-identity-2026-11-16.md). `make spec-bindings`.

import (
	"crypto/x509"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// device is a device certificate of person for app (either "": none).
func (o *testOrg) device(t testing.TB, name, person, app string, groups ...string) *x509.Certificate {
	t.Helper()
	tmpl := leafTemplate(t, o.orgID, name, groups, t0)
	if person != "" {
		tmpl.EmailAddresses = []string{person}
	}
	if app != "" {
		tmpl.URIs = append(tmpl.URIs, &url.URL{Scheme: "nfltr", Host: Domain(o.orgID), Path: appURIPath + app})
	}
	return mint(t, tmpl, o.iss, newKey(t).Public(), o.issKey)
}

var appIdentityBindings = map[string]func(t *testing.T){
	"app.attrs": func(t *testing.T) {
		o := newTestOrg(t, t0)
		o.takeCRL(t, t0)
		at := t0.Add(time.Minute)
		want := Peer{Users: []string{"alice@example.com"}, Apps: []string{"send"}}
		id, err := o.ver.Check(o.device(t, "send-1", "alice@example.com", "send", "web"), o.iss, want, at)
		if err != nil || id.Person != "alice@example.com" || id.App != "send" {
			t.Fatalf("alice's send: %+v, %v", id, err)
		}
		// The relay routes the session to another device of the
		// organisation: another person, another app, or a machine
		// enrolled for neither.
		for what, c := range map[string]*x509.Certificate{
			"bob's send":        o.device(t, "send-2", "bob@example.com", "send", "web"),
			"alice's other app": o.device(t, "desk-1", "alice@example.com", "desk", "web"),
			"a plain machine":   o.device(t, "web-1", "", "", "web"),
		} {
			if _, err := o.ver.Check(c, o.iss, want, at); err == nil || !strings.Contains(err.Error(), "not admitted") {
				t.Errorf("%s: %v, want not admitted", what, err)
			}
		}
	},
	"app.urihost": func(t *testing.T) {
		o := newTestOrg(t, t0)
		o.takeCRL(t, t0)
		tmpl := leafTemplate(t, o.orgID, "send-1", []string{"web"}, t0)
		tmpl.URIs = append(tmpl.URIs, &url.URL{Scheme: "nfltr", Host: Domain("o-other"), Path: appURIPath + "send"})
		c := mint(t, tmpl, o.iss, newKey(t).Public(), o.issKey)
		if _, err := o.ver.Check(c, o.iss, Peer{}, t0.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "outside the organisation") {
			t.Fatalf("an app URI of another organisation: %v, want refused", err)
		}
	},
}

// TestAppEnrolModelBindingsAttrs runs every row; each is a BIND id of the
// model.
func TestAppEnrolModelBindingsAttrs(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/app_enrol.pv")
	if err != nil {
		t.Fatal(err)
	}
	for id, row := range appIdentityBindings {
		if !strings.Contains(string(src), "BIND:"+id+" ") {
			t.Errorf("app_enrol.pv declares no BIND:%s", id)
		}
		t.Run(id, row)
	}
}

// PersonOf and AppOf read one SAN each: none, or two, is "".
func TestPersonAndAppOfOneSAN(t *testing.T) {
	o := newTestOrg(t, t0)
	c := o.device(t, "send-1", "alice@example.com", "send", "web")
	if PersonOf(c) != "alice@example.com" || AppOf(c) != "send" || MachineID(c) != "m-send-1" {
		t.Fatalf("person %q app %q machine %q", PersonOf(c), AppOf(c), MachineID(c))
	}
	c.EmailAddresses = append(c.EmailAddresses, "bob@example.com")
	c.URIs = append(c.URIs, &url.URL{Scheme: "nfltr", Host: Domain(o.orgID), Path: appURIPath + "desk"})
	if PersonOf(c) != "" || AppOf(c) != "" {
		t.Fatalf("two SANs: person %q app %q, want none", PersonOf(c), AppOf(c))
	}
	// A service that names no person and no app admits a plain machine
	// as before.
	o.takeCRL(t, t0)
	if _, err := o.ver.Check(o.device(t, "web-1", "", "", "web"), o.iss, Peer{Group: "web"}, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}
