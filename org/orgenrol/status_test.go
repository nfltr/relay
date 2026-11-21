// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"
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
	serial := f.joined.Cert.SerialNumber.Text(16)
	o, err := orgpki.RevokeOrder(pins, f.org.rootKey, "web-1", serial, f.clk.Now())
	check(t, err)
	post := func(id string) orgpki.Answer {
		t.Helper()
		data, err := json.Marshal(orgpki.Request{ID: id, Order: &o})
		check(t, err)
		_, err = f.relay.Append(f.ctx, orgpki.EnrolMailbox(f.org.id), data, mailboxclient.AppendOptions{})
		check(t, err)
		deadline := time.Now().Add(hang)
		for time.Now().Before(deadline) {
			f.relay.mu.Lock()
			for _, e := range f.relay.boxes[orgpki.AnswersMailbox(f.org.id)] {
				var a orgpki.Answer
				if json.Unmarshal(e.Payload, &a) == nil && a.ID == id {
					f.relay.mu.Unlock()
					return a
				}
			}
			f.relay.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("no answer to %s", id)
		return orgpki.Answer{}
	}
	if a := post("order-1"); a.Revoked != "web-1" || a.Refused != "" {
		t.Fatalf("the order's answer: %+v", a)
	}
	if a := post("order-2"); a.Revoked != "" || a.Refused == "" {
		t.Fatalf("the same order again: %+v, want refused", a)
	}
	deadline := time.Now().Add(hang)
	for st := f.status(t); st == nil || len(st.Members) == 0 || !st.Members[0].Revoked; st = f.status(t) {
		if time.Now().After(deadline) {
			t.Fatal("the status never showed web-1 revoked")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
