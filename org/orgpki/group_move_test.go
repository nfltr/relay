// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The root's move order (nfltr docs/decisions/one-group-2026-11-25.md;
// relay-server spec/GroupMirror.tla Move, MovedOnlyAsked, PeerStaleBound;
// spec/proverif/orggroup.pv queries 3 and 5): the issuer moves a member
// into new groups only by the root's signed order, revokes every
// certificate of it so far in the next CRL, signs the status only after
// that CRL, and the member's renewal brings the new groups. Mutants in
// testdata/mutants.txt.

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

func serialOf(c *x509.Certificate) string { return hex.EncodeToString(c.SerialNumber.Bytes()) }

func (o *org) pins() Pins { return Pins{OrgID: o.iss.OrgID(), Root: o.rootCrt, Issuer: o.iss.Cert()} }

// moveOrder is the root's honest order moving name at c's serial into groups.
func (o *org) moveOrder(t *testing.T, name string, c *x509.Certificate, groups []string, at time.Time) SignedOrder {
	t.Helper()
	s, err := MoveOrder(o.pins(), o.root, name, serialOf(c), groups, at)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// renew renews c (key k) for a fresh key at at.
func (o *org) renew(t *testing.T, c *x509.Certificate, k ed25519.PrivateKey, at time.Time) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	k2 := newKey(t)
	der, err := o.iss.Renew(NewRenewRequest(c.Raw, k, csr(t, k2, c.Subject.CommonName)), at)
	if err != nil {
		t.Fatalf("renewing %s: %v", c.Subject.CommonName, err)
	}
	return parse(t, der), k2
}

// MovedOnlyAsked, PeerStaleBound (mutant move-keeps-old-cert): web-1 in
// web, renewed once (two certificates valid), moved to db: the next CRL
// lists both, the peers refuse both, its renewal from the revoked one is
// certified in db and admitted for db only. A replay of the order moves
// nothing (mutant move-replayed); the log's replay holds the move.
func TestMoveOrderRegroupsAndRevokesTheOldCertificates(t *testing.T) {
	o := newOrg(t)
	c1, k1 := o.enrol(t, "web-1", "web")
	at := t0.Add(MachineLife / 2)
	c2, k2 := o.renew(t, c1, k1, at)
	order := o.moveOrder(t, "web-1", c2, []string{"db"}, at)
	got, err := o.iss.ApplyOrder(order, at)
	if err != nil || got.Name != "web-1" || got.Act != ActMoveOrder {
		t.Fatalf("the honest move: %+v, %v", got, err)
	}
	o.takeCRL(t, at)
	for _, c := range []*x509.Certificate{c1, c2} {
		if _, err := o.ver.Check(c, o.iss.Cert(), orgid.Peer{Group: "web"}, at); err == nil {
			t.Errorf("serial %s from before the move admitted", serialOf(c))
		}
	}
	c3, _ := o.renew(t, c2, k2, at) // the keeper's renewal from its revoked certificate
	if !slices.Equal(c3.Subject.OrganizationalUnit, []string{"db"}) {
		t.Fatalf("renewed into groups %v, want [db]", c3.Subject.OrganizationalUnit)
	}
	if _, err := o.ver.Check(c3, o.iss.Cert(), orgid.Peer{Group: "db"}, at); err != nil {
		t.Fatalf("the moved machine's new certificate for db: %v", err)
	}
	if _, err := o.ver.Check(c3, o.iss.Cert(), orgid.Peer{Group: "web"}, at); err == nil {
		t.Error("the moved machine's new certificate admitted for web")
	}
	if _, err := o.iss.ApplyOrder(order, at); !errors.Is(err, ErrRefused) {
		t.Errorf("the same order again: %v, want refused", err)
	}
	back := o.moveOrder(t, "web-1", c2, []string{"web"}, at)
	if _, err := o.iss.ApplyOrder(back, at); !errors.Is(err, ErrRefused) {
		t.Errorf("an order naming a serial moved already: %v, want refused", err)
	}
	replayed, err := Open(o.lines, o.iss.key, o.sink)
	if err != nil {
		t.Fatal(err)
	}
	if n := replayed.names["web-1"]; !slices.Equal(n.groups, []string{"db"}) || n.moved != 2 {
		t.Fatalf("the log's replay: groups %v, moved %d", n.groups, n.moved)
	}
}

// MovedOnlyAsked: only the root's order of this organisation, unexpired,
// for a current serial, into groups within the issuer's bound and not
// the member's already, moves it (mutants move-outside-bound).
func TestMoveOrderRefusals(t *testing.T) {
	o := newOrg(t)
	c, _ := o.enrol(t, "web-1", "web")
	db, _ := o.enrol(t, "db-1", "db")
	for what, s := range map[string]SignedOrder{
		"outside the issuer's bound": o.moveOrder(t, "web-1", c, []string{"ops"}, t0),
		"the groups it holds":        o.moveOrder(t, "web-1", c, []string{"web"}, t0),
		"another member's serial":    o.moveOrder(t, "web-1", db, []string{"db"}, t0),
		"an expired order":           o.moveOrder(t, "web-1", c, []string{"db"}, t0.Add(-OrderLife)),
	} {
		if _, err := o.iss.ApplyOrder(s, t0); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v, want refused", what, err)
		}
	}
	if _, err := MoveOrder(o.pins(), o.root, "web-1", serialOf(c), nil, t0); err == nil {
		t.Error("a move order without groups signed")
	}
	if n := o.iss.names["web-1"]; !slices.Equal(n.groups, []string{"web"}) || n.moved != 0 {
		t.Fatalf("a refused order changed web-1: groups %v, moved %d", n.groups, n.moved)
	}
}

// GroupMirror.tla Sign (mutant status-before-crl): after a move the
// status waits for the CRL revoking the old certificate, then shows the
// new groups with that CRL.
func TestStatusWaitsForTheMovesCRL(t *testing.T) {
	o := newOrg(t)
	c, _ := o.enrol(t, "web-1", "web")
	o.takeCRL(t, t0)
	if _, err := o.iss.ApplyOrder(o.moveOrder(t, "web-1", c, []string{"db"}, t0), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.SignedStatus(t0); !errors.Is(err, ErrCRLDue) {
		t.Fatalf("the status before the move's CRL: %v, want ErrCRLDue", err)
	}
	der, err := o.iss.CRL(t0)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(crl.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool { return e.SerialNumber.Cmp(c.SerialNumber) == 0 }) {
		t.Fatal("the move's CRL does not list the old certificate")
	}
	s, err := o.iss.SignedStatus(t0)
	if err != nil {
		t.Fatal(err)
	}
	st, _, err := VerifyStatus(s, o.rootCrt)
	if err != nil {
		t.Fatal(err)
	}
	if st.CRL.Number != crl.Number.Int64() || len(st.Members) != 1 || !slices.Equal(st.Members[0].Groups, []string{"db"}) {
		t.Fatalf("status CRL %d (want %d), members %+v", st.CRL.Number, crl.Number, st.Members)
	}
}

// GroupMirror.tla Move (mutant rebind-token-groups): a rebind token made
// before a move certifies the name's groups at its redemption, not the
// groups it was made with: else the status says db while a valid
// certificate the CRL does not list says web.
func TestRebindAfterAMoveTakesTheNewGroups(t *testing.T) {
	o := newOrg(t)
	c, _ := o.enrol(t, "web-1", "web")
	tok, err := o.iss.MakeRebindToken("web-1", "m-web-2", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.iss.ApplyOrder(o.moveOrder(t, "web-1", c, []string{"db"}, t0), t0); err != nil {
		t.Fatal(err)
	}
	req, err := NewEnrolRequest(tok, csr(t, newKey(t), "web-1"))
	if err != nil {
		t.Fatal(err)
	}
	der, err := o.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	if got := parse(t, der).Subject.OrganizationalUnit; !slices.Equal(got, []string{"db"}) {
		t.Fatalf("the rebind after the move certified groups %v, want [db]", got)
	}
}
