// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"net/url"
	"strings"
	"testing"
)

// shortNameCases is the rule's table; org/orgpki's TestValidShortName
// carries the same rows (its copy of the rule).
var shortNameCases = map[string]bool{
	"acme": true, "a": true, "acme-corp": true, "a1": true, strings.Repeat("a", 63): true,
	"": false, "o-x": false, "o-": false, "Acme": false, "1acme": false, "-acme": false,
	"acme-": false, "ac_me": false, "ac.me": false, strings.Repeat("a", 64): false,
}

func TestValidShortName(t *testing.T) {
	for s, want := range shortNameCases {
		if got := ValidShortName(s); got != want {
			t.Errorf("ValidShortName(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestShortNameFallsBackToOrgID(t *testing.T) {
	o := newTestOrg(t, t0)
	if got := ShortName(o.root); got != o.orgID {
		t.Fatalf("no short name: ShortName = %q, want the id %q", got, o.orgID)
	}
	tmpl := caTemplate(t, rootCNPrefix+o.orgID, t0, 0)
	name := func(s string) *url.URL {
		return &url.URL{Scheme: "nfltr", Host: Domain(o.orgID), Path: nameURIPath + s}
	}
	for what, c := range map[string]struct {
		uris []*url.URL
		want string
	}{
		"one":     {[]*url.URL{name("acme")}, "acme"},
		"o-":      {[]*url.URL{name("o-evil")}, o.orgID},
		"upper":   {[]*url.URL{name("Acme")}, o.orgID},
		"two":     {[]*url.URL{name("acme"), name("other")}, o.orgID},
		"machine": {[]*url.URL{{Scheme: "nfltr", Host: Domain(o.orgID), Path: machineURIPath + "acme"}}, o.orgID},
	} {
		tmpl.URIs = c.uris
		r := mint(t, tmpl, tmpl, o.rootKey.Public(), o.rootKey)
		if got := ShortName(r); got != c.want {
			t.Errorf("%s: ShortName = %q, want %q", what, got, c.want)
		}
	}
}
