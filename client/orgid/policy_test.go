// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The agent's access rules come from the newest signed status it took,
// while that status is fresh (relay-server spec/GroupMirror.tla
// PeerTake, PeerRuleAdmits; mutants peer-rule-unsigned, peer-rule-older,
// peer-rule-no-expiry); a newer status without the rule cuts a held
// session (W_RuleRemoved).
func TestAccessRulesFromTheSignedStatus(t *testing.T) {
	now := time.Now()
	o := newTestOrg(t, now)
	d := t.TempDir()
	o.enrolDir(t, filepath.Join(d, "web"), "web", now, "web")
	cli := o.enrolDir(t, filepath.Join(d, "cli"), "cli", now, "db")
	web := load(t, filepath.Join(d, "web"))
	chain := []*x509.Certificate{cli, o.iss}
	svc := []string{"pg"}
	if _, err := web.CheckClient(chain, svc, now); err == nil || !strings.Contains(err.Error(), "no access rules") {
		t.Fatalf("no status yet: %v, want fail closed", err)
	}
	allowRules := []Rule{{Who: "group:db", Where: "group:web", Service: "pg"}}
	allow := o.policy(t, Policy{Number: 1, Rules: allowRules})
	none := o.policy(t, Policy{Number: 2})
	next := now.Add(crlLife)
	at := now.Add(-time.Minute)
	if took, err := web.TakeStatus(o.status(t, at, next, &allow), now); !took || err != nil {
		t.Fatalf("the honest status: %v %v", took, err)
	}
	until, err := web.CheckClient(chain, svc, now)
	if err != nil || until.After(next) {
		t.Fatalf("admitted by the rule: until %v, %v", until, err)
	}
	if _, err := web.CheckClient(chain, []string{"ssh"}, now); err == nil || !strings.Contains(err.Error(), "nfltr access allow") {
		t.Errorf("another service: %v, want refused naming the command", err)
	}
	// Refused: another root's status, a lapsed one, an older one.
	other := newTestOrg(t, now)
	other.orgID = o.orgID
	if _, err := web.TakeStatus(other.status(t, now, next, &none), now); err == nil {
		t.Error("a status under another root taken")
	}
	if _, err := web.TakeStatus(o.status(t, now, now.Add(-time.Second), &none), now); err == nil {
		t.Error("a lapsed status taken")
	}
	if took, _ := web.TakeStatus(o.status(t, at.Add(-time.Minute), next, &allow), now); took {
		t.Error("an older status taken")
	}
	if _, err := web.CheckClient(chain, svc, now); err != nil {
		t.Fatalf("the rule went with a refused status: %v", err)
	}
	// A held session is checked again at the newer rules (signed in the
	// same instant: the rules' number orders them) and refused; older
	// rules under a later status are not taken back.
	changed := web.Changed()
	if took, err := web.TakeStatus(o.status(t, at, next, &none), now); !took || err != nil {
		t.Fatalf("the newer rules: %v %v", took, err)
	}
	if took, _ := web.TakeStatus(o.status(t, at.Add(time.Minute), next, &allow), now); took {
		t.Error("older rules taken back under a later status")
	}
	select {
	case <-changed:
	default:
		t.Fatal("a taken status signalled no change")
	}
	if _, err := web.CheckClient(chain, svc, now); err == nil {
		t.Error("the removed rule still admits")
	}
	// Past the status's life every rule session fails closed, the
	// certificate and its CRL still good.
	soon := now.Add(10 * time.Minute)
	again := o.policy(t, Policy{Number: 3, Rules: allowRules})
	if _, err := web.TakeStatus(o.status(t, at.Add(2*time.Minute), soon, &again), now); err != nil {
		t.Fatal(err)
	}
	if until, err := web.CheckClient(chain, svc, now); err != nil || !until.Equal(soon) {
		t.Fatalf("until %v, %v: want the status's life", until, err)
	}
	if _, err := web.CheckClient(chain, svc, soon.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "access rules lapsed") {
		t.Errorf("past the status's life: %v, want the rules lapsed", err)
	}
}

// A policy a root may sign names typed principals and places only.
func TestPolicyValid(t *testing.T) {
	ok := Policy{OrgID: "o-1", Number: 1, Rules: []Rule{{Who: "person:alice@acme.com", Where: "machine:h", Service: AnyService}}}
	if err := ok.Valid(); err != nil {
		t.Fatal(err)
	}
	for what, r := range map[string]Rule{
		"untyped who":   {Who: "ops", Where: "machine:h", Service: "pg"},
		"person place":  {Who: "group:ops", Where: "person:a@b", Service: "pg"},
		"empty service": {Who: "group:ops", Where: "machine:h"},
		"slash in name": {Who: "group:o/ps", Where: "machine:h", Service: "pg"},
		"slash service": {Who: "group:ops", Where: "machine:h", Service: "a/b"},
		"unknown kind":  {Who: "app:send", Where: "machine:h", Service: "pg"},
		"empty name":    {Who: "group:", Where: "machine:h", Service: "pg"},
	} {
		p := ok
		p.Rules = []Rule{r}
		if p.Valid() == nil {
			t.Errorf("%s: valid", what)
		}
	}
	if (Policy{OrgID: "o-1"}).Valid() == nil {
		t.Error("number 0 valid")
	}
}
