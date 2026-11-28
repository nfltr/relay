// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// A grant org: bob asks, alice approves crm/web (the root's policy), carol
// is a member who approves nothing; crm serves web.
type grantOrg struct {
	*org
	bob, alice, carol, crm member
}

type member struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func (o *org) member(t *testing.T, name, person string, groups ...string) member {
	t.Helper()
	tok, err := o.iss.MakeDeviceToken(name, groups, "m-"+name, Device{Person: person}, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	req, err := NewEnrolRequest(tok, csr(t, k, name))
	if err != nil {
		t.Fatal(err)
	}
	der, err := o.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	return member{parse(t, der), k}
}

func newGrantOrg(t *testing.T) *grantOrg {
	t.Helper()
	o := &grantOrg{org: newOrg(t)}
	o.bob = o.member(t, "bob-mac", "bob@acme.com", "web")
	o.alice = o.member(t, "alice-mac", "alice@acme.com", "web")
	o.carol = o.member(t, "carol-mac", "carol@acme.com", "web")
	o.crm = o.member(t, "crm", "", "db")
	o.approvers(t, 1, "bob@acme.com", "alice@acme.com") // bob too: self-approval has a target
	o.takeCRL(t, t0)
	return o
}

func (o *grantOrg) approvers(t *testing.T, n int64, people ...string) {
	t.Helper()
	sp, err := SignPolicy(o.root, orgid.Policy{OrgID: o.iss.OrgID(), Number: n,
		Approvers: []orgid.Approver{{Where: "machine:crm", Service: "web", People: people}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.TakePolicy(sp, t0); err != nil {
		t.Fatal(err)
	}
}

func (o *grantOrg) act(t *testing.T, m *member, a GrantAct, at time.Time) (GrantAnswer, error) {
	t.Helper()
	a.OrgID = o.iss.OrgID()
	var key crypto.Signer = o.root
	var cert []byte
	if m != nil {
		key, cert = m.key, m.cert.Raw
	}
	r, err := SignGrant(a, key, cert, at)
	if err != nil {
		t.Fatal(err)
	}
	return o.iss.ApplyGrant(r, at)
}

// ask is bob's request for crm/web for d, with its digest from the status.
func (o *grantOrg) ask(t *testing.T, id string, d time.Duration, at time.Time) StatusGrantRequest {
	t.Helper()
	if _, err := o.act(t, &o.bob, GrantAct{Act: GrantAsk, ID: id, Where: "machine:crm", Service: "web", ForS: int64(d / time.Second), Reason: "INC-1"}, at); err != nil {
		t.Fatal(err)
	}
	for _, r := range o.status(t, at).Requests {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("request %s not in the status", id)
	return StatusGrantRequest{}
}

func (o *grantOrg) status(t *testing.T, at time.Time) Status {
	t.Helper()
	s, err := o.iss.SignedStatus(at)
	if err != nil {
		t.Fatal(err)
	}
	st, _, err := VerifyStatus(s, o.rootCrt)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func (o *grantOrg) grantCert(t *testing.T, serial string, at time.Time) *x509.Certificate {
	t.Helper()
	for _, g := range o.status(t, at).Grants {
		if g.Serial == serial {
			return parse(t, g.Cert)
		}
	}
	t.Fatalf("grant %s not in the status", serial)
	return nil
}

// admit is crm's admission of bob's session to web by the grant g.
func (o *grantOrg) admit(t *testing.T, client member, g *x509.Certificate, service string, at time.Time) (time.Time, error) {
	t.Helper()
	var rules orgid.Rules // no rule: only a grant admits
	self := orgid.Checked{Name: o.crm.cert.Subject.CommonName, Groups: o.crm.cert.Subject.OrganizationalUnit}
	return orgid.AdmitClient(o.ver, &rules, []*x509.Certificate{client.cert, o.iss.Cert(), g}, self, []string{service}, at)
}

// A request, an approval and the grant: signed for the requester's key and
// person, the request's service and duration (Grant.tla Sign), carried in
// the status (a reopened issuer's too), admitted by the serving agent until
// its end (Open), and only then.
func TestGrantRequestApproveAdmit(t *testing.T) {
	o := newGrantOrg(t)
	at := t0.Add(time.Minute)
	r := o.ask(t, "req-00000001", 4*time.Hour, at)
	if r.Who != "person:bob@acme.com" || r.Where != "machine:crm" || r.Service != "web" || r.ForS != 4*3600 {
		t.Fatalf("the status's request: %+v", r)
	}
	ans, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if want := at.Add(time.Minute + 4*time.Hour); !ans.Until.Equal(want) {
		t.Errorf("until %s, want the request's 4h from the approval: %s", ans.Until, want)
	}
	st := o.status(t, at.Add(2*time.Minute))
	if len(st.Requests) != 0 || len(st.Grants) != 1 || st.Grants[0].By != "alice@acme.com" {
		t.Fatalf("status after the approval: %+v %+v", st.Requests, st.Grants)
	}
	g := o.grantCert(t, ans.Serial, at.Add(2*time.Minute))
	gr, ok := orgid.GrantOf(g)
	if !ok || gr.Who != "person:bob@acme.com" || gr.Where != "machine:crm" || gr.Service != "web" || gr.By != "alice@acme.com" || gr.Request != r.ID {
		t.Fatalf("the grant certificate: %+v %v", gr, ok)
	}
	o.takeCRL(t, at.Add(2*time.Minute))
	until, err := o.admit(t, o.bob, g, "web", at.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if until.After(ans.Until) {
		t.Errorf("admitted until %s, past the grant's %s", until, ans.Until)
	}
	if _, err := o.admit(t, o.bob, g, "web", ans.Until); err == nil {
		t.Error("admitted at the grant's end (Grant.tla ExpiryBound)")
	}
	if _, err := o.ver.Check(g, o.iss.Cert(), orgid.Peer{}, at.Add(3*time.Minute)); err == nil {
		t.Error("a grant certificate passed as a machine's")
	}
	reopened, err := Open(o.lines, o.iss.key, o.sink)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := reopened.SignedStatus(at.Add(3 * time.Minute))
	rst, _, _ := VerifyStatus(s, o.rootCrt)
	if len(rst.Grants) != 1 || rst.Grants[0].Serial != ans.Serial {
		t.Errorf("the reopened issuer's grants: %+v", rst.Grants)
	}
}

// The issuer answers a request once (ApprovalOnce, DenyFinal), only by an
// approver the root's policy names who is not the requester
// (GrantMatchesApproval), over the whole request (svc.apprall), and takes
// only a member machine's request for one service and a bounded time.
func TestGrantRefusals(t *testing.T) {
	o := newGrantOrg(t)
	at := t0.Add(time.Minute)
	r := o.ask(t, "req-00000001", time.Hour, at)
	refusedBy := func(what, want string, _ GrantAnswer, err error) {
		t.Helper()
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want refused: %s", what, err, want)
		}
	}
	a, err := o.act(t, &o.bob, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at)
	refusedBy("self-approval", "own request", a, err)
	a, err = o.act(t, &o.carol, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at)
	refusedBy("a member no policy names", "not an approver", a, err)
	a, err = o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: r.ID, Digest: strings.Repeat("0", 64)}, at)
	refusedBy("an approval of another request body", "not over the request", a, err)
	a, err = o.act(t, nil, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at)
	refusedBy("the owner's approval (the owner names approvers)", "not an approver", a, err)
	if _, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at); err != nil {
		t.Fatal(err)
	}
	a, err = o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at)
	refusedBy("a replayed approval", "answered already", a, err)

	d := o.ask(t, "req-00000002", time.Hour, at)
	if _, err := o.act(t, &o.alice, GrantAct{Act: GrantDeny, ID: d.ID, Digest: d.Digest}, at); err != nil {
		t.Fatal(err)
	}
	a, err = o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: d.ID, Digest: d.Digest}, at)
	refusedBy("an approval after the deny", "answered already (denied)", a, err)
	n := o.ask(t, "req-00000003", time.Hour, at)
	if _, err := o.act(t, nil, GrantAct{Act: GrantDeny, ID: n.ID, Digest: n.Digest}, at); err != nil {
		t.Errorf("the owner's deny: %v", err)
	}

	for what, c := range map[string]struct {
		m   *member
		a   GrantAct
		why string
	}{
		"a reused id":         {&o.bob, GrantAct{Act: GrantAsk, ID: r.ID, Where: "machine:crm", Service: "web", ForS: 60}, "not a new one"},
		"every service":       {&o.bob, GrantAct{Act: GrantAsk, ID: "req-00000010", Where: "machine:crm", Service: "*", ForS: 60}, "not one service"},
		"a person as a place": {&o.bob, GrantAct{Act: GrantAsk, ID: "req-00000011", Where: "person:x@acme.com", Service: "web", ForS: 60}, "not one service"},
		"too long":            {&o.bob, GrantAct{Act: GrantAsk, ID: "req-00000012", Where: "machine:crm", Service: "web", ForS: int64(MaxGrantFor/time.Second) + 1}, "at most"},
		"the root's request":  {nil, GrantAct{Act: GrantAsk, ID: "req-00000013", Where: "machine:crm", Service: "web", ForS: 60}, "member machine's"},
	} {
		a, err := o.act(t, c.m, c.a, at)
		refusedBy(what, c.why, a, err)
	}
}

// A revoke lists the grant on the next CRL until it ends, and the agent
// that takes that CRL refuses it (Grant.tla Revoke, Publish, Deliver:
// RevokeBound); removing the grant's person revokes it the same way (lead
// decision 2026-11-26); only an approver, the holder or the owner revokes.
func TestGrantRevokedAndRemoved(t *testing.T) {
	o := newGrantOrg(t)
	at := t0.Add(time.Minute)
	grant := func(id string) GrantAnswer {
		r := o.ask(t, id, 2*time.Hour, at)
		a, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	g1, g2 := grant("req-00000001"), grant("req-00000002")
	c1, c2 := o.grantCert(t, g1.Serial, at), o.grantCert(t, g2.Serial, at)
	if _, err := o.act(t, &o.carol, GrantAct{Act: GrantRevoke, ID: g1.Serial}, at); !errors.Is(err, ErrRefused) {
		t.Errorf("carol revoked bob's grant: %v", err)
	}
	if _, err := o.act(t, &o.alice, GrantAct{Act: GrantRevoke, ID: g1.Serial}, at); err != nil {
		t.Fatal(err)
	}
	if !o.iss.CRLDue() {
		t.Error("no CRL due after a revoke: the agents would hear of it at the next renewal only")
	}
	listed := func(at time.Time) map[string]bool {
		der, err := o.iss.CRL(at)
		if err != nil {
			t.Fatal(err)
		}
		if err := o.ver.TakeCRL(der, o.iss.Cert(), at); err != nil {
			t.Fatal(err)
		}
		crl, _ := x509.ParseRevocationList(der)
		m := map[string]bool{}
		for _, e := range crl.RevokedCertificateEntries {
			m[hex.EncodeToString(e.SerialNumber.Bytes())] = true
		}
		return m
	}
	if l := listed(at.Add(time.Minute)); !l[g1.Serial] || l[g2.Serial] {
		t.Fatalf("CRL after the revoke: %v", l)
	}
	if _, err := o.admit(t, o.bob, c1, "web", at.Add(2*time.Minute)); err == nil {
		t.Error("a revoked grant admitted")
	}
	if _, err := o.admit(t, o.bob, c2, "web", at.Add(2*time.Minute)); err != nil {
		t.Errorf("the other grant: %v", err)
	}
	if _, err := o.iss.RevokePerson("bob@acme.com", at.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if l := listed(at.Add(4 * time.Minute)); !l[g2.Serial] {
		t.Errorf("bob removed, his grant %s not on the CRL", g2.Serial)
	}
	if st := o.status(t, at.Add(4*time.Minute)); len(st.Grants) != 0 {
		t.Errorf("the status lists a removed person's grants: %+v", st.Grants)
	}
	if l := listed(g1.Until); l[g1.Serial] {
		t.Error("a grant that ended is still listed")
	}
}

// A removed approver's approvals end with them (People.tla
// NoGrantOfRemoved, mutant removal-keeps-approvals): the grant alice
// approved for bob is on the next CRL once alice is removed; bob stays.
func TestGrantApprovalsEndWithTheApprover(t *testing.T) {
	o := newGrantOrg(t)
	at := t0.Add(time.Minute)
	r := o.ask(t, "req-00000001", 2*time.Hour, at)
	a, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at)
	if err != nil {
		t.Fatal(err)
	}
	g := o.grantCert(t, a.Serial, at)
	if _, err := o.iss.RevokePerson("alice@acme.com", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	o.takeCRL(t, at.Add(2*time.Minute))
	if _, err := o.admit(t, o.bob, g, "web", at.Add(2*time.Minute)); err == nil {
		t.Error("a grant its removed approver approved still admits")
	}
	if st := o.status(t, at.Add(2*time.Minute)); len(st.Grants) != 0 {
		t.Errorf("the status lists a removed approver's grant: %+v", st.Grants)
	}
}

// The holder's key: a grant presented by another machine, or for another
// person, admits nothing (svc.grantwho, more rows in the bindings test).
func TestGrantForItsHolderOnly(t *testing.T) {
	o := newGrantOrg(t)
	at := t0.Add(time.Minute)
	r := o.ask(t, "req-00000001", time.Hour, at)
	a, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at)
	if err != nil {
		t.Fatal(err)
	}
	g := o.grantCert(t, a.Serial, at)
	o.takeCRL(t, at)
	if _, err := o.admit(t, o.carol, g, "web", at); err == nil {
		t.Error("carol's machine admitted by bob's grant")
	}
	if _, err := o.admit(t, o.bob, g, "ssh", at); err == nil {
		t.Error("bob admitted to another service by a grant for web")
	}
}

// A CRL past its NextUpdate admits no grant session (Grant.tla Fresh:
// mutant stale-list-admits), and the admission ends at it (Tick:
// stale-list-keeps).
func TestGrantStaleListRefused(t *testing.T) {
	o := newGrantOrg(t)
	at := t0.Add(time.Minute)
	r := o.ask(t, "req-00000001", 48*time.Hour, at) // outlives the CRL
	a, err := o.act(t, &o.alice, GrantAct{Act: GrantApprove, ID: r.ID, Digest: r.Digest}, at)
	if err != nil {
		t.Fatal(err)
	}
	g := o.grantCert(t, a.Serial, at)
	o.takeCRL(t, at)
	id, err := o.ver.Check(o.bob.cert, o.iss.Cert(), orgid.Peer{}, at)
	if err != nil {
		t.Fatal(err)
	}
	self := orgid.Checked{Name: "crm"}
	_, until, err := o.ver.CheckGrant(g, o.iss.Cert(), o.bob.cert, id, self, []string{"web"}, at)
	if err != nil {
		t.Fatal(err)
	}
	next := at.Add(CRLLife)
	if until.After(next) {
		t.Errorf("admitted until %s, past the CRL's next update %s", until, next)
	}
	id.Until = next.Add(time.Hour) // the client's certificate aside
	if _, _, err := o.ver.CheckGrant(g, o.iss.Cert(), o.bob.cert, id, self, []string{"web"}, next); err == nil {
		t.Error("a grant admitted under a lapsed CRL")
	}
}
