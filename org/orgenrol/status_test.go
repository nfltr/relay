// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
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

// The root's renewal answer (nfltr org approve of a renew wish), posted on
// the enrol drop box, is installed: the issuer's certificate moves on and
// the status shows the new NotAfter; the same answer again is refused, an
// old answer (OrgDash.tla Apply, mutant install-old; InstallRenewal).
func TestServiceInstallsTheRootsRenewal(t *testing.T) {
	f := newFleetWith(t, func(f *fleet) { f.copy = true })
	var pins orgpki.Pins
	var req orgpki.IssuerRenewalRequest
	var was time.Time
	f.org.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) {
		pins = orgpki.Pins{OrgID: iss.OrgID(), Root: iss.Root(), Issuer: iss.Cert()}
		was = iss.Cert().NotAfter
		var err error
		req, err = iss.RenewalRequest(iss.Groups())
		check(t, err)
	})
	f.clk.Add(time.Hour)
	ans, err := orgpki.SignIssuerRenewal(pins, f.org.rootKey, req, false, f.clk.Now())
	check(t, err)
	until, err := SendRenewal(f.ctx, f.relay, f.org.id, ans, hang)
	if err != nil || !until.After(was) {
		t.Fatalf("the renewal: until %v (was %v), %v", until, was, err)
	}
	if _, err := SendRenewal(f.ctx, f.relay, f.org.id, ans, hang); !errors.Is(err, ErrIssuerRefused) {
		t.Fatalf("the same answer again: %v, want refused", err)
	}
	deadline := time.Now().Add(hang)
	for st := f.status(t); st == nil || !issuerNotAfter(t, st).Equal(until); st = f.status(t) {
		if time.Now().After(deadline) {
			t.Fatal("the status never showed the renewed issuer")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func issuerNotAfter(t *testing.T, st *orgpki.Status) time.Time {
	t.Helper()
	c, err := x509.ParseCertificate(st.Issuer)
	check(t, err)
	return c.NotAfter
}

func (r copyRelay) OrgStatus(_ context.Context, orgID string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.statuses[orgID]), nil
}

// The root's access policy reaches a kept machine: the issuer takes it
// from the drop box, carries it in the status it puts on the relay's copy
// and pushes a CRL, whose take wakes the keeper's read of the copy
// (relay-server spec/GroupMirror.tla RuleApply, PeerTake). The machine
// then admits a client of group web to pg, as the rule says, and no other
// service (lane SA3).
func TestKeptMachineTakesTheRootsAccessRules(t *testing.T) {
	f := newFleetWith(t, func(f *fleet) { f.copy = true })
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	keep(t, ctx, f.keeper())
	cur, _ := f.m.Current()
	chain := []*x509.Certificate{cur, issuerOf(t, f.dir)}
	if _, err := f.m.CheckClient(chain, []string{"pg"}, f.clk.Now()); err == nil {
		t.Fatal("admitted with no rule")
	}
	sp, err := orgpki.SignPolicy(f.org.rootKey, orgid.Policy{OrgID: f.org.id, Number: 1,
		Rules: []orgid.Rule{{Who: "group:web", Where: "machine:web-1", Service: "pg"}}})
	check(t, err)
	if _, err := SendPolicy(f.ctx, f.relay, f.org.id, sp, hang); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the rule reaches the machine", func() bool {
		_, err := f.m.CheckClient(chain, []string{"pg"}, f.clk.Now())
		return err == nil
	})
	if _, err := f.m.CheckClient(chain, []string{"ssh"}, f.clk.Now()); err == nil {
		t.Error("a service no rule names admitted")
	}
}

// An issuer whose log lost its last lines does not serve: the relay's
// copy of its status names a head the log lacks (orgpki.ErrTruncated;
// lane SECFIX2, review S19, mutant truncation-served). The whole log
// serves.
func TestIssuerWithALostTailDoesNotServe(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	o := newOrg(t, now)
	var st orgpki.SignedStatus
	o.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) {
		_, err := iss.MakeToken("web-1", []string{"web"}, "", time.Hour, now)
		check(t, err)
		st, err = iss.SignedStatus(now)
		check(t, err)
	})
	msg, err := json.Marshal(st)
	check(t, err)
	r := newRelay()
	r.statuses = map[string][]byte{o.id: msg}
	run := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		return Service{Mailbox: copyRelay{r}, Dir: o.dir, Logger: quiet(), Now: func() time.Time { return now }, Wait: 50 * time.Millisecond}.Run(ctx)
	}
	if err := run(); err != nil {
		t.Fatalf("the whole log: %v", err)
	}
	log := filepath.Join(o.dir, orgissuer.LogFile)
	data, err := os.ReadFile(log)
	check(t, err)
	lines := bytes.SplitAfter(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	check(t, os.WriteFile(log, bytes.Join(lines[:len(lines)-1], nil), 0o600))
	if err := run(); !errors.Is(err, orgpki.ErrTruncated) {
		t.Fatalf("a log without its last line: %v, want ErrTruncated", err)
	}
}
