// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgpki"
)

func (r copyRelay) PutOrgStatus(_ context.Context, orgID string, msg []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.statuses == nil {
		r.statuses = map[string][]byte{}
	}
	r.statuses[orgID] = slices.Clone(msg)
	return nil
}

// status is the relay's copy of the organisation's status, verified under
// its root as `nfltr org status --relay` reads it (nil: none yet).
func (f *fleet) status(t *testing.T) *orgpki.Status {
	t.Helper()
	f.relay.mu.Lock()
	data := f.relay.statuses[f.org.id]
	f.relay.mu.Unlock()
	if data == nil {
		return nil
	}
	var s orgpki.SignedStatus
	check(t, json.Unmarshal(data, &s))
	st, _, err := orgpki.VerifyStatus(s, f.org.root(t))
	check(t, err)
	return &st
}

// The issuer service puts its signed status on the relay's copy and puts
// it again when it changes: a revoke shows (org-dashboard-2026-11-21.md
// "Status"; OrgDash.tla Publish).
func TestServicePutsItsStatus(t *testing.T) {
	f := newFleetWith(t, func(f *fleet) { f.copy = true })
	member := func(st *orgpki.Status) *orgpki.StatusMember {
		if st == nil {
			return nil
		}
		for i := range st.Members {
			if st.Members[i].Name == "web-1" {
				return &st.Members[i]
			}
		}
		return nil
	}
	waitFor := func(what string, ok func(*orgpki.StatusMember) bool) {
		t.Helper()
		deadline := time.Now().Add(hang)
		for !ok(member(f.status(t))) {
			if time.Now().After(deadline) {
				t.Fatalf("the relay's status copy never showed %s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor("web-1 enrolled", func(m *orgpki.StatusMember) bool { return m != nil && !m.Revoked })
	if _, err := orgissuer.RevokeMachines(f.org.dir, []string{"m-web-1"}, f.clk.Now()); err != nil {
		t.Fatal(err)
	}
	waitFor("web-1 revoked", func(m *orgpki.StatusMember) bool { return m != nil && m.Revoked })
}

// The root's order to revoke a member, posted on the enrol drop box as the
// root's machine does (nfltr org approve), is applied and answered; the
// status shows the member revoked; the same order again revokes nothing
// (OrgDash.tla Apply; orgdash.pv 3).
func TestServiceAppliesTheRootsOrder(t *testing.T) {
	f := newFleetWith(t, func(f *fleet) { f.copy = true })
	var pins orgpki.Pins
	f.org.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) {
		pins = orgpki.Pins{OrgID: iss.OrgID(), Root: iss.Root(), Issuer: iss.Cert()}
	})
	serial := hex.EncodeToString(f.joined.Cert.SerialNumber.Bytes())
	o, err := orgpki.RevokeOrder(pins, f.org.rootKey, "web-1", serial, f.clk.Now())
	check(t, err)
	if name, err := SendOrder(f.ctx, f.relay, f.org.id, o, hang); err != nil || name != "web-1" {
		t.Fatalf("the order: %q, %v", name, err)
	}
	if name, err := SendOrder(f.ctx, f.relay, f.org.id, o, hang); !errors.Is(err, ErrIssuerRefused) || name != "" {
		t.Fatalf("the same order again: %q, %v, want refused", name, err)
	}
	deadline := time.Now().Add(hang)
	for st := f.status(t); st == nil || len(st.Members) == 0 || !st.Members[0].Revoked; st = f.status(t) {
		if time.Now().After(deadline) {
			t.Fatal("the status never showed web-1 revoked")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
