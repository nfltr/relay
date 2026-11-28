// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
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

// A root rotation carries the organisation's access policy: in the same
// act the new root signs again the policy the old root signed, so the
// members' agents, which take only the pinned root's rules (client/orgid
// Rules, review S5), admit after the rotation as before it. A policy the
// old root did not sign is never signed again: the rotation is refused
// (relay-server spec/GroupMirror.tla Rotate, RulesUnderRoot,
// RotateKeepsRules, ResignOnlySigned: mutants rotate-drops-rules,
// rotate-carries-unsigned; lane ROTATERULES).
func TestRotationCarriesTheRootsPolicy(t *testing.T) {
	o := newOrg(t)
	want := orgid.Policy{OrgID: o.iss.OrgID(), Number: 3, Rules: []orgid.Rule{{Who: "group:web", Where: "group:db", Service: "pg"}},
		Approvers: []orgid.Approver{{Where: "group:db", Service: "pg", People: []string{"ann@example.com"}}}}
	sp, err := SignPolicy(o.root, want)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.TakePolicy(sp, t0); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(time.Hour)

	// A policy in the log the old root never signed (another key's, a line
	// written behind the issuer): the rotation refuses it, nothing changes.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged, err := SignPolicy(other, orgid.Policy{OrgID: o.iss.OrgID(), Number: 4, Rules: []orgid.Rule{{Who: "group:db", Where: "group:db", Service: orgid.AnyService}}})
	if err != nil {
		t.Fatal(err)
	}
	held := o.iss.policy
	o.iss.policy = &forged
	cross, nk := rotate(t, o, at, o.rec, o.iss.Recovery())
	if err := o.iss.Rotate(cross, "org-2", nk, newKey(t), o.groups, at); !errors.Is(err, ErrRefused) {
		t.Fatalf("a rotation over a policy the old root did not sign: %v, want refused", err)
	}
	if !o.iss.Root().Equal(o.rootCrt) {
		t.Fatal("the refused rotation moved the root")
	}
	o.iss.policy = held

	ikey := newKey(t)
	if err := o.iss.Rotate(cross, "org-2", nk, ikey, o.groups, at); err != nil {
		t.Fatal(err)
	}
	if err := o.ver.TakeRotation(cross.Raw); err != nil {
		t.Fatal(err)
	}
	o.takeCRL(t, at) // the new issuer's first publish
	reopened, err := Open(o.lines, ikey, o.sink)
	if err != nil {
		t.Fatal(err)
	}
	for name, iss := range map[string]*Issuer{"issuer": o.iss, "reopened": reopened} {
		if p, err := iss.Policy(); err != nil || !reflect.DeepEqual(p, want) {
			t.Errorf("%s: policy after the rotation %+v, %v; want %+v", name, p, err, want)
		}
		s, err := iss.SignedStatus(at.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		st, _, err := VerifyStatus(s, cross)
		if err != nil || st.Policy == nil {
			t.Fatalf("%s: status %v, policy %v", name, err, st.Policy)
		}
		if _, err := orgid.VerifyPolicy(*st.Policy, o.rootCrt, o.iss.OrgID()); err == nil {
			t.Errorf("%s: the status carries the old root's signature", name)
		}
		// A member's agent pinning the new root takes the rules.
		msg, _ := json.Marshal(s)
		var r orgid.Rules
		if took, err := r.Take(msg, o.ver, at.Add(time.Minute)); !took || err != nil {
			t.Errorf("%s: the agent takes the status after the rotation: %v %v", name, took, err)
		}
	}
	// The new root's next policy is numbered on from the carried one.
	if _, err := o.iss.TakePolicy(sp, at); !errors.Is(err, ErrRefused) {
		t.Errorf("the old root's policy after the rotation: %v, want refused", err)
	}
	next, _ := SignPolicy(nk, orgid.Policy{OrgID: o.iss.OrgID(), Number: 4, Rules: want.Rules})
	if n, err := o.iss.TakePolicy(next, at); n != 4 || err != nil {
		t.Errorf("the new root's next policy: %d %v", n, err)
	}
}
