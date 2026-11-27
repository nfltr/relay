// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/appenrol"
	"github.com/nfltr/relay/client/appenrol/idptest"
	"github.com/nfltr/relay/client/mailboxclient"
	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgpki"
)

// An enrolment by sign-in reaches the issuer service over the mailboxes
// and is answered with the person's device certificate (orgpki
// EnrolSignIn; spec/appenrol/AppEnrol.tla EnrolSSO).
func TestSignInThroughMailboxes(t *testing.T) {
	f := newFleet(t)
	idp := idptest.New("alice@example.com")
	defer idp.Close()
	f.org.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) {
		check(t, iss.AddSignInRule(orgpki.SignInRule{ID: "people", Issuer: idp.URL, ClientIDs: []string{"send-desktop"}, App: "send", Groups: []string{"web"}}, f.clk.Now()))
	})
	kr, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	_, ko, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	nonce, err := appenrol.Nonce(kr.Public(), ko.Public())
	check(t, err)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ko)
	check(t, err)
	sr, err := orgpki.NewSignInRequest("people", idp.Token(idp.Claims("send-desktop", nonce)), csr, kr.Public())
	check(t, err)
	if a, err := exchange(f.ctx, f.relay, f.org.id, orgpki.Request{ID: randomID(), SignIn: &sr}, hang); err == nil {
		t.Fatalf("a sign-in with no invite enrolled %x", a.Cert)
	}
	check(t, sr.ProveInvite(f.invite(t, "alice@example.com", orgpki.RoleMember)))
	a, err := exchange(f.ctx, f.relay, f.org.id, orgpki.Request{ID: randomID(), SignIn: &sr}, hang)
	check(t, err)
	c, err := x509.ParseCertificate(a.Cert)
	check(t, err)
	if c.Subject.CommonName != "send-1" || !slices.Equal(c.EmailAddresses, []string{"alice@example.com"}) {
		t.Fatalf("certificate %s for %v", c.Subject.CommonName, c.EmailAddresses)
	}
}

// JoinSignIn: the device's side of a sign-in over the mailboxes, the
// answer checked and installed, renewed as any machine; run again with the
// same key it keeps its name.
func TestJoinSignInInstallsTheDevice(t *testing.T) {
	f := newFleet(t)
	idp := idptest.New("alice@example.com")
	defer idp.Close()
	f.org.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) {
		check(t, iss.AddSignInRule(orgpki.SignInRule{ID: "people", Issuer: idp.URL, ClientIDs: []string{"send-desktop"}, App: "send", Groups: []string{"web"}}, f.clk.Now()))
	})
	kr, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	_, ko, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	nonce, err := appenrol.Nonce(kr.Public(), ko.Public())
	check(t, err)
	dir := filepath.Join(t.TempDir(), "device")
	invite := f.invite(t, "alice@example.com", orgpki.RoleMember)
	for range 2 {
		c, err := JoinSignIn(f.ctx, f.relay, dir, f.org.pins, f.org.id, "people", idp.Token(idp.Claims("send-desktop", nonce)), invite, ko, kr.Public(), hang, f.clk.Now)
		invite = "" // the same key again: a sign-in again, no invite
		check(t, err)
		if c.Subject.CommonName != "send-1" {
			t.Fatalf("enrolled as %s", c.Subject.CommonName)
		}
	}
	m, err := orgmachine.Open(dir)
	check(t, err)
	before := serial(m)
	f.clk.Add(17 * time.Hour)
	check(t, Keeper{Mailbox: f.relay, Machine: m, Logger: quiet(), Now: f.clk.Now, AnswerWait: hang, RetryWait: 10 * time.Millisecond}.renew(f.ctx, ""))
	if serial(m) == before {
		t.Fatal("the device did not renew")
	}
	if _, err := JoinSignIn(f.ctx, f.relay, filepath.Join(t.TempDir(), "x"), f.org.pins, f.org.id, "people", idp.Token(idp.Claims("rogue", nonce)), "", ko, kr.Public(), hang, f.clk.Now); err == nil {
		t.Fatal("a rogue client's token joined")
	}
}

// A renewal refused because its sign-in ended is ErrSignInEnded on the
// device too (Answer.SignInEnded), so the app knows to sign in again.
func TestSignInEndedIsTypedOnTheDevice(t *testing.T) {
	r := newRelay()
	b, err := json.Marshal(orgpki.Answer{ID: "r1", Refused: "refused: " + orgpki.ErrSignInEnded.Error(), SignInEnded: true})
	check(t, err)
	_, err = r.Append(context.Background(), orgpki.AnswersMailbox("o-x"), b, mailboxclient.AppendOptions{})
	check(t, err)
	if _, err := exchange(context.Background(), r, "o-x", orgpki.Request{ID: "r1"}, hang); !errors.Is(err, orgpki.ErrSignInEnded) {
		t.Fatalf("exchange: %v, want ErrSignInEnded", err)
	}
}

// invite is the owner's invite of person as role, the root's act carried
// over the mailboxes (orgpki.ApplyPeople).
func (f *fleet) invite(t *testing.T, person, role string) string {
	t.Helper()
	invite, key, err := orgpki.NewInvite(f.org.id)
	check(t, err)
	var head string // the signer reads it from the status
	f.org.do(t, func(iss *orgpki.Issuer, _ *orgissuer.Store) { head = iss.Head() })
	pr, err := orgpki.SignPeople(orgpki.PeopleAct{OrgID: f.org.id, Head: head, Act: orgpki.PeopleInvite, Person: person, Role: role, InviteKey: key}, f.org.rootKey, nil, f.clk.Now())
	check(t, err)
	if _, err := exchange(f.ctx, f.relay, f.org.id, orgpki.Request{ID: randomID(), People: &pr}, hang); err != nil {
		t.Fatalf("the invite: %v", err)
	}
	return invite
}
