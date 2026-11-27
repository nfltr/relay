// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// The issuer takes the root's access policy only as the root signed it,
// newer than the one held, logs it, and carries it in every signed status
// from then, a reopened issuer too (relay-server spec/GroupMirror.tla
// RuleApply, RuleOnlyAsked: mutant rule-without-root).
func TestIssuerCarriesTheRootsPolicy(t *testing.T) {
	o := newOrg(t)
	pol := func(n int64, who string) orgid.Policy {
		return orgid.Policy{OrgID: o.iss.OrgID(), Number: n, Rules: []orgid.Rule{{Who: who, Where: "group:db", Service: "pg"}}}
	}
	sp, err := SignPolicy(o.root, pol(1, "group:web"))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := o.iss.TakePolicy(sp, t0); n != 1 || err != nil {
		t.Fatalf("the root's policy: %d %v", n, err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged, err := SignPolicy(other, pol(2, "group:db"))
	if err != nil {
		t.Fatal(err)
	}
	for what, p := range map[string]orgid.SignedPolicy{"replayed": sp, "another key's": forged} {
		if n, err := o.iss.TakePolicy(p, t0); !errors.Is(err, ErrRefused) || n != 1 {
			t.Errorf("%s policy: %d %v, want refused at 1", what, n, err)
		}
	}
	reopened, err := Open(o.lines, o.iss.key, o.sink)
	if err != nil {
		t.Fatal(err)
	}
	for name, iss := range map[string]*Issuer{"issuer": o.iss, "reopened": reopened} {
		s, err := iss.SignedStatus(t0.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		st, _, err := VerifyStatus(s, o.rootCrt)
		if err != nil || st.Policy == nil {
			t.Fatalf("%s: status %v, policy %v", name, err, st.Policy)
		}
		p, err := orgid.VerifyPolicy(*st.Policy, o.rootCrt, o.iss.OrgID())
		if err != nil || p.Number != 1 || p.Rules[0].Who != "group:web" {
			t.Errorf("%s: carried %+v, %v", name, p, err)
		}
		if !iss.CRLDue() {
			t.Errorf("%s: no CRL due: the members would read the status late", name)
		}
	}
	// The status a member's agent takes carries it (client/orgid TakeStatus).
	s, _ := o.iss.SignedStatus(t0.Add(time.Minute))
	msg, _ := json.Marshal(s)
	var back SignedStatus
	if json.Unmarshal(msg, &back) != nil || string(back.Body) != string(s.Body) {
		t.Fatal("the status message does not round-trip")
	}
}
