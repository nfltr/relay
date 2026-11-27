// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

// The signed policy's bindings of spec/proverif/svc_access.pv (lane SA3,
// nfltr docs/decisions/service-access-2026-11-25.md "2. Policy"): a rule
// admits only under the root's key and for the client's certified
// principal (BIND:svc.rulesig, query 4; mutants rule-unsigned,
// group-from-client), and an approver counts only as the root's policy
// names it for that service (BIND:svc.apprpol, query 2; mutant
// policy-unsigned). Each row changes one field of the honest message and
// requires a refusal. The other svc.* ids are other lanes' rows (SA2:
// client/agent, SA4: org/orgpki). `make spec-bindings`.

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/nfltr/relay/client/internal/modelbind"
)

var svcAccessBindings = map[string]func(t *testing.T){
	"svc.rulesig": func(t *testing.T) {
		o := newTestOrg(t, t0)
		o.takeCRL(t, t0)
		at := t0.Add(time.Minute)
		bob, _ := o.enrol(t, "bob", "ci")
		self := Checked{Name: "h", Groups: []string{"db"}}
		id, err := o.ver.Check(bob, o.iss, Peer{}, at)
		check(t, err)
		rule := Rule{Who: "group:ci", Where: "machine:h", Service: "pg"}
		honest := o.policy(t, Policy{Rules: []Rule{rule}})
		p, err := VerifyPolicy(honest, o.root, o.orgID)
		if err != nil || !p.Admits(id, self, "pg") {
			t.Fatalf("the honest rule: %v", err)
		}
		// The relay offers a rule of its own making, or another
		// organisation's, or alters the signed body.
		other := newTestOrg(t, t0)
		forged := other.policy(t, Policy{OrgID: o.orgID, Rules: []Rule{rule}})
		altered := honest
		altered.Body = []byte(string(honest.Body[:len(honest.Body)-1]) + " ")
		for what, sp := range map[string]SignedPolicy{
			"another root's":      forged,
			"altered":             altered,
			"another org's":       o.policy(t, Policy{OrgID: "o-other", Rules: []Rule{rule}}),
			"no signature at all": {Body: honest.Body},
		} {
			if _, err := VerifyPolicy(sp, o.root, o.orgID); err == nil {
				t.Errorf("%s policy taken", what)
			}
		}
		// The rule is for the certified principal only: another group, a
		// machine named as the group, another service, another place.
		eve, _ := o.enrol(t, "ci", "web")
		eveID, err := o.ver.Check(eve, o.iss, Peer{}, at)
		check(t, err)
		for what, c := range map[string]struct {
			id   Checked
			self Checked
			svc  string
		}{
			"a machine named ci in group web": {eveID, self, "pg"},
			"another service":                 {id, self, "ssh"},
			"another machine":                 {id, Checked{Name: "h2", Groups: []string{"db"}}, "pg"},
		} {
			if p.Admits(c.id, c.self, c.svc) {
				t.Errorf("%s admitted", what)
			}
		}
	},
	"svc.apprpol": func(t *testing.T) {
		o := newTestOrg(t, t0)
		honest := o.policy(t, Policy{Approvers: []Approver{{Where: "machine:h", Service: "web", People: []string{"alice@acme.com"}}}})
		p, err := VerifyPolicy(honest, o.root, o.orgID)
		if err != nil || !p.Approves("alice@acme.com", "machine:h", "web") {
			t.Fatalf("the honest approver: %v", err)
		}
		for what, a := range map[string][3]string{
			"another person":  {"mallory@acme.com", "machine:h", "web"},
			"another service": {"alice@acme.com", "machine:h", "pg"},
			"another place":   {"alice@acme.com", "group:h", "web"},
			"nobody":          {"", "machine:h", "web"},
		} {
			if p.Approves(a[0], a[1], a[2]) {
				t.Errorf("%s approves", what)
			}
		}
		forged := newTestOrg(t, t0).policy(t, Policy{OrgID: o.orgID, Approvers: []Approver{{Where: "machine:h", Service: "web", People: []string{"mallory@acme.com"}}}})
		if _, err := VerifyPolicy(forged, o.root, o.orgID); err == nil {
			t.Error("approvers another root signed taken")
		}
	},
}

// TestSvcAccessModelBindingsPolicy runs every row; each is a BIND id of
// the model, the SA3 ones.
func TestSvcAccessModelBindingsPolicy(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/svc_access.pv")
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for id, row := range svcAccessBindings {
		rows = append(rows, id)
		t.Run(id, row)
	}
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:(svc\.(?:rulesig|apprpol))\s`), rows); err != nil {
		t.Fatal(err)
	}
}
