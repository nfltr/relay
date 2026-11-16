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
	"slices"
	"testing"

	"github.com/nfltr/relay/client/appenrol"
	"github.com/nfltr/relay/client/appenrol/idptest"
	"github.com/nfltr/relay/client/mailboxclient"
	"github.com/nfltr/relay/org/orgissuer"
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
	a, err := exchange(f.ctx, f.relay, f.org.id, orgpki.Request{ID: randomID(), SignIn: &sr}, hang)
	check(t, err)
	c, err := x509.ParseCertificate(a.Cert)
	check(t, err)
	if c.Subject.CommonName != "send-1" || !slices.Equal(c.EmailAddresses, []string{"alice@example.com"}) {
		t.Fatalf("certificate %s for %v", c.Subject.CommonName, c.EmailAddresses)
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
