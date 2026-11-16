// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

// The verifier's bindings of spec/proverif/orghosted.pv (BIND:hosted.*;
// the time bound is spec/orgmove/OrgHosted.tla's): each row changes one
// binding of an honest check, as a relay or a stolen issuer key can, and
// requires a refusal. `make spec-bindings`.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/internal/modelbind"
)

var hostedBindings = map[string]func(t *testing.T){
	// A chain through an issuer the root's CRL of issuers lists is refused
	// (mutant ignore-root-crl); a CRL of issuers another key signed is not
	// taken (mutant root-crl-unsigned), nor an older one after a newer.
	"hosted.rootcrl": func(t *testing.T) {
		o := newTestOrg(t, t0)
		web, _ := o.enrol(t, "web-1", "web")
		o.takeCRL(t, t0)
		at := t0.Add(time.Minute)
		check(t, o.ver.TakeIssuerCRL(o.issuersCRL(t, 1, t0, nil)))
		if _, err := o.ver.Check(web, o.iss, Peer{Name: "web-1"}, at); err != nil {
			t.Fatalf("web-1 under an issuer the root did not revoke: %v", err)
		}
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		check(t, err)
		refused(t, "a CRL of issuers the root did not sign", o.ver.TakeIssuerCRL(o.issuersCRL(t, 3, t0, other, o.iss)))
		check(t, o.ver.TakeIssuerCRL(o.issuersCRL(t, 2, t0, nil, o.iss)))
		if _, err := o.ver.Check(web, o.iss, Peer{Name: "web-1"}, at); err == nil || !strings.Contains(err.Error(), "revoked this issuer") {
			t.Fatalf("web-1 under a revoked issuer: %v, want refused", err)
		}
		refused(t, "an older CRL of issuers", o.ver.TakeIssuerCRL(o.issuersCRL(t, 1, t0, nil)))
	},
	// A leaf a stolen issuer key signed past the issuer's NotAfter is
	// admitted only until the issuer's NotAfter, and refused past it (mutant
	// until-leaf-only; finding F1).
	"hosted.until": func(t *testing.T) {
		o := newTestOrg(t, t0)
		at := o.iss.NotAfter.Add(-time.Minute)
		forged := mint(t, leafTemplate(t, o.orgID, "web-1", []string{"web"}, at), o.iss, newKey(t).Public(), o.issKey)
		o.takeCRL(t, at)
		id, err := o.ver.Check(forged, o.iss, Peer{Name: "web-1"}, at)
		check(t, err)
		if id.Until.After(o.iss.NotAfter) {
			t.Fatalf("Until %s, after the issuer's NotAfter %s", id.Until, o.iss.NotAfter)
		}
		_, err = o.ver.Check(forged, o.iss, Peer{Name: "web-1"}, o.iss.NotAfter.Add(time.Second))
		refused(t, "the forged leaf past the issuer's NotAfter", err)
	},
}

// TestOrgHostedModelBindings runs every row; each is a BIND id of the
// model.
func TestOrgHostedModelBindings(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/orghosted.pv")
	if err != nil {
		t.Fatal(err)
	}
	rows := slices.Sorted(maps.Keys(hostedBindings))
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:(hosted\.[a-z0-9.]+)`), rows); err != nil {
		t.Fatal(err)
	}
	for _, id := range rows {
		t.Run(id, hostedBindings[id])
	}
}
