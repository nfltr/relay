// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// An app's device enrolled by a person's sign-in (nfltr
// docs/decisions/app-device-identity-2026-11-16.md; spec/appenrol/AppEnrol.tla
// EnrolSSO, Renew, Reauth; spec/proverif/app_enrol.pv IssuerSSO) against
// the in-process IdP (client/appenrol/idptest).

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/appenrol"
	"github.com/nfltr/relay/client/appenrol/idptest"
)

const client = "send-desktop"

type signInOrg struct {
	*org
	idp     *idptest.IdP
	now     time.Time
	invites map[string]string // by email: the owner's invite (people.go), made at the person's first sign-in
}

func newSignInOrg(t *testing.T, email string) *signInOrg {
	t.Helper()
	s := &signInOrg{org: newOrg(t), idp: idptest.New(email), now: t0, invites: map[string]string{}}
	t.Cleanup(s.idp.Close)
	s.idp.Now = func() time.Time { return s.now }
	if err := s.iss.AddSignInRule(SignInRule{ID: "people", Issuer: s.idp.URL, ClientIDs: []string{client, "send-mobile"},
		App: "send", Groups: []string{"web"}}, t0); err != nil {
		t.Fatal(err)
	}
	return s
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func csrOf(t *testing.T, k crypto.Signer, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// device is an app's two keys on one device.
type device struct {
	kr *ecdsa.PrivateKey
	ko crypto.Signer
}

func newDevice(t *testing.T) device { return device{newP256(t), newKey(t)} }

// token is the IdP's ID token for the device's keys, claims changed by edit.
func (s *signInOrg) token(t *testing.T, d device, edit func(map[string]any)) string {
	t.Helper()
	nonce, err := appenrol.Nonce(d.kr.Public(), d.ko.Public())
	if err != nil {
		t.Fatal(err)
	}
	c := s.idp.Claims(client, nonce)
	if edit != nil {
		edit(c)
	}
	return s.idp.Token(c)
}

func (s *signInOrg) request(t *testing.T, d device, tok string) SignInRequest {
	t.Helper()
	req, err := NewSignInRequest("people", tok, csrOf(t, d.ko, "admin"), d.kr.Public())
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// enrol signs d in with the token edit makes, proving the owner's invite
// of the token's person (made at its first sign-in): a join for a new
// key, ignored for a key enrolled.
func (s *signInOrg) enrol(t *testing.T, d device, edit func(map[string]any)) ([]byte, error) {
	t.Helper()
	email := "alice@example.com"
	req := s.request(t, d, s.token(t, d, func(c map[string]any) {
		if edit != nil {
			edit(c)
		}
		email, _ = c["email"].(string)
	}))
	if err := req.ProveInvite(s.inviteOf(t, email)); err != nil {
		t.Fatal(err)
	}
	return s.iss.EnrolSignIn(context.Background(), req, s.now)
}

// inviteOf is email's invite as a member, made by the owner once.
func (s *signInOrg) inviteOf(t *testing.T, email string) string {
	t.Helper()
	email = strings.ToLower(email)
	if s.invites[email] == "" {
		s.invites[email] = s.ownerInvite(t, email, RoleMember)
	}
	return s.invites[email]
}

// The SDK's sign-in (code + PKCE against the IdP) enrols the device: the
// certificate names the token's person and the rule's app under a name
// the issuer picks (never the request's CN), the log keeps the rule and
// the sign-in's end, and the same keys signing in again keep their name.
func TestSignInEnrolsPersonAndApp(t *testing.T) {
	s := newSignInOrg(t, "Alice@Example.com")
	d := newDevice(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := appenrol.SignIn(ctx, appenrol.SignInConfig{Issuer: s.idp.URL, ClientID: client, RelayKey: d.kr.Public(), OrgKey: d.ko.Public(),
		Open: func(u string) error {
			resp, err := http.Get(u)
			if err == nil {
				resp.Body.Close()
			}
			return err
		}})
	if err != nil {
		t.Fatal(err)
	}
	req := s.request(t, d, tok)
	if err := req.ProveInvite(s.inviteOf(t, "alice@example.com")); err != nil {
		t.Fatal(err)
	}
	der, err := s.iss.EnrolSignIn(ctx, req, s.now)
	if err != nil {
		t.Fatal(err)
	}
	c := parse(t, der)
	if c.Subject.CommonName != "send-1" || !slices.Equal(c.EmailAddresses, []string{"alice@example.com"}) || appURI(c) != "send" ||
		!slices.Equal(c.Subject.OrganizationalUnit, []string{"web"}) {
		t.Fatalf("certificate %s person %v app %q groups %v", c.Subject.CommonName, c.EmailAddresses, appURI(c), c.Subject.OrganizationalUnit)
	}
	if again, err := s.enrol(t, d, nil); err != nil || parse(t, again).Subject.CommonName != "send-1" {
		t.Fatalf("the same keys again: %v", err)
	}
	if _, err := s.enrol(t, newDevice(t), nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("another device by sign-in alone: %v, want refused (an invite is for a new person)", err)
	}
	re, err := Open(s.lines, s.iss.key, s.sink)
	if err != nil {
		t.Fatal(err)
	}
	if rs := re.SignInRules(); len(rs) != 1 || rs[0].ID != "people" || !slices.Equal(rs[0].ClientIDs, []string{client, "send-mobile"}) {
		t.Fatalf("rules after replay %+v", rs)
	}
	if got := re.names["send-1"].authUntil; !got.Equal(t0.Add(AuthLife)) {
		t.Fatalf("authUntil after replay %s", got)
	}
}

// The issuer side of app_enrol.pv's IssuerSSO: each row changes one field
// a relay (or a rogue client at the same IdP) controls and requires a
// refusal. `make spec-bindings`.
var signInBindings = map[string]func(t *testing.T){
	// The nonce names the request's two keys (mutant signin-no-nonce-check).
	"app.nonce": func(t *testing.T) {
		s := newSignInOrg(t, "alice@example.com")
		d := newDevice(t)
		tok := s.token(t, d, nil)
		for what, x := range map[string]device{
			"org key swapped":   {d.kr, newKey(t)},
			"relay key swapped": {newP256(t), d.ko},
		} {
			req := s.request(t, x, tok) // the invite proved over the swapped keys: only the nonce refuses
			if err := req.ProveInvite(s.inviteOf(t, "alice@example.com")); err != nil {
				t.Fatal(err)
			}
			if _, err := s.iss.EnrolSignIn(context.Background(), req, s.now); !errors.Is(err, ErrRefused) {
				t.Errorf("%s: %v, want refused", what, err)
			}
		}
	},
	// aud (and azp) among the rule's client ids: a rogue client's token is
	// refused (mutant no-aud-check).
	"app.aud": func(t *testing.T) {
		s := newSignInOrg(t, "alice@example.com")
		for what, edit := range map[string]func(map[string]any){
			"rogue client":     func(c map[string]any) { c["aud"] = "rogue" },
			"rogue azp":        func(c map[string]any) { c["aud"], c["azp"] = []string{client, "rogue"}, "rogue" },
			"no audience held": func(c map[string]any) { c["aud"] = []string{} },
		} {
			if _, err := s.enrol(t, newDevice(t), edit); !errors.Is(err, ErrRefused) {
				t.Errorf("%s: %v, want refused", what, err)
			}
		}
		if _, err := s.enrol(t, newDevice(t), func(c map[string]any) { c["aud"] = "send-mobile" }); err != nil {
			t.Errorf("the rule's other client: %v", err)
		}
	},
	// The token is the rule's IdP's, signed by its key and unexpired
	// (mutant no-token-exp).
	"app.idtoken": func(t *testing.T) {
		s := newSignInOrg(t, "alice@example.com")
		d := newDevice(t)
		nonce, _ := appenrol.Nonce(d.kr.Public(), d.ko.Public())
		forged := idptest.SignWith(newP256(t), s.idp.Claims(client, nonce))
		if _, err := s.iss.EnrolSignIn(context.Background(), s.request(t, d, forged), s.now); !errors.Is(err, ErrRefused) {
			t.Errorf("another key's token: %v, want refused", err)
		}
		for what, edit := range map[string]func(map[string]any){
			"another issuer": func(c map[string]any) { c["iss"] = "https://idp.example" },
			"expired":        func(c map[string]any) { c["exp"] = s.now.Add(-time.Minute).Unix() },
			"unverified":     func(c map[string]any) { c["email_verified"] = false },
		} {
			if _, err := s.enrol(t, newDevice(t), edit); !errors.Is(err, ErrRefused) {
				t.Errorf("%s: %v, want refused", what, err)
			}
		}
	},
}

// TestAppEnrolSignInModelBindings runs every row; each is a BIND id of
// app_enrol.pv.
func TestAppEnrolSignInModelBindings(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/app_enrol.pv")
	if err != nil {
		t.Fatal(err)
	}
	for id, row := range signInBindings {
		if !strings.Contains(string(src), "BIND:"+id+" ") {
			t.Errorf("app_enrol.pv declares no BIND:%s", id)
		}
		t.Run(id, row)
	}
}

// renewDaily renews the newest certificate every 20 hours until until
// (the issuer certificate, IssuerLife, renewed by the root every 10
// days); it returns the last certificate, its key and the first refusal.
func renewDaily(t *testing.T, o *org, der []byte, k crypto.Signer, from, until time.Time) ([]byte, crypto.Signer, time.Time, error) {
	t.Helper()
	at := from
	for at.Before(until) {
		at = at.Add(20 * time.Hour)
		if o.iss.Cert().NotAfter.Sub(at) < 20*24*time.Hour {
			if err := o.iss.RenewIssuer(o.root, o.groups, at); err != nil {
				t.Fatal(err)
			}
		}
		iss := o.iss
		nk := newKey(t)
		csr := csrOf(t, nk, "x")
		sig, err := k.Sign(rand.Reader, renewMessageOf(t, k, csr), cryptoOpts(k))
		if err != nil {
			t.Fatal(err)
		}
		nd, err := iss.Renew(RenewRequest{Cert: der, CSR: csr, Sig: sig}, at)
		if err != nil {
			return der, k, at, err
		}
		der, k = nd, nk
	}
	return der, k, at, nil
}

// renewMessageOf is what k signs for a renewal: the message itself
// (Ed25519) or its SHA-256 (ECDSA).
func renewMessageOf(t *testing.T, k crypto.Signer, csr []byte) []byte {
	t.Helper()
	m := renewMessage(csr)
	if _, ok := k.(*ecdsa.PrivateKey); ok {
		sum := sha256.Sum256(m)
		return sum[:]
	}
	return m
}

func cryptoOpts(k crypto.Signer) crypto.SignerOpts {
	if _, ok := k.(*ecdsa.PrivateKey); ok {
		return crypto.SHA256
	}
	return crypto.Hash(0)
}

// codeDevice enrols name for person and app send by an admin code.
func (s *signInOrg) codeDevice(t *testing.T, name, person string) ([]byte, crypto.Signer) {
	t.Helper()
	k := newKey(t)
	tok, err := s.iss.MakeDeviceToken(name, []string{"web"}, "", Device{Person: person, App: "send"}, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewEnrolRequest(tok, csrOf(t, k, name))
	if err != nil {
		t.Fatal(err)
	}
	der, err := s.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	return der, k
}

// AppEnrol.tla Renew and Reauth (mutant renew-ignores-auth): a key
// enrolled by sign-in renews by itself until AuthLife after the sign-in,
// then is refused with ErrSignInEnded; the person signing in again with
// that key moves it on. A code-enrolled key renews past it.
func TestSignInRenewalEndsWithAuthLife(t *testing.T) {
	s := newSignInOrg(t, "alice@example.com")
	d := newDevice(t)
	der, err := s.enrol(t, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	der, k, at, err := renewDaily(t, s.org, der, d.ko, t0, t0.Add(AuthLife+48*time.Hour))
	if !errors.Is(err, ErrSignInEnded) || !errors.Is(err, ErrRefused) || !at.After(t0.Add(AuthLife)) || at.After(t0.Add(AuthLife+20*time.Hour)) {
		t.Fatalf("renewal at %s: %v, want ErrSignInEnded just past AuthLife", at, err)
	}
	s.now = at
	again, err := s.enrol(t, device{d.kr, k}, nil)
	if err != nil {
		t.Fatalf("sign-in again with the current key: %v", err)
	}
	if parse(t, again).Subject.CommonName != parse(t, der).Subject.CommonName {
		t.Fatal("the sign-in again named another device")
	}
	if _, _, _, err := renewDaily(t, s.org, again, k, at, at.Add(48*time.Hour)); err != nil {
		t.Fatalf("renewal after the sign-in again: %v", err)
	}
	cd, ck := s.codeDevice(t, "code-1", "bob@example.com")
	if _, _, _, err := renewDaily(t, s.org, cd, ck, t0, t0.Add(AuthLife+48*time.Hour)); err != nil {
		t.Fatalf("a code-enrolled device past AuthLife: %v", err)
	}
}

// AppEnrol.tla Reauth (mutant reauth-any-user) and EnrolSSO's deny lists
// (mutant signin-skips-deny): another person's sign-in with a device's
// key does not move that device's sign-in on, nor does a sign-in with a
// code-enrolled key (mutant signin-takes-code-key) or a revoked device's;
// a revoked person or app signs in no device.
func TestSignInOnlyForItsPersonNotRevoked(t *testing.T) {
	s := newSignInOrg(t, "alice@example.com")
	d := newDevice(t)
	if _, err := s.enrol(t, d, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enrol(t, d, func(c map[string]any) { c["email"], c["sub"] = "bob@example.com", "sub-bob" }); !errors.Is(err, ErrRefused) {
		t.Fatalf("bob's sign-in with alice's device key: %v, want refused", err)
	}
	_, ck := s.codeDevice(t, "code-1", "alice@example.com")
	if _, err := s.enrol(t, device{d.kr, ck}, nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("a sign-in with a code-enrolled key: %v, want refused", err)
	}
	d2 := newDevice(t)
	bob := func(c map[string]any) { c["email"], c["sub"] = "bob@example.com", "sub-bob" }
	der2, err := s.enrol(t, d2, bob)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.iss.Revoke(parse(t, der2).Subject.CommonName, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enrol(t, d2, bob); !errors.Is(err, ErrRefused) {
		t.Fatalf("a sign-in with a revoked device's key: %v, want refused", err)
	}
	if _, err := s.iss.RevokePerson("alice@example.com", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enrol(t, newDevice(t), nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("a revoked person's sign-in: %v, want refused", err)
	}
	if err := s.iss.RevokeApp("send", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enrol(t, newDevice(t), func(c map[string]any) { c["email"], c["sub"] = "carol@example.com", "sub-carol" }); !errors.Is(err, ErrRefused) {
		t.Fatalf("a revoked app's sign-in: %v, want refused", err)
	}
}

// A device key in a Secure Enclave or TPM is P-256 (owner decision,
// app-device-identity open question 3): enrolled by sign-in and renewed
// with its ECDSA signature.
func TestSignInP256DeviceKey(t *testing.T) {
	s := newSignInOrg(t, "alice@example.com")
	d := device{newP256(t), newP256(t)}
	der, err := s.enrol(t, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parse(t, der).PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatal("not a P-256 certificate")
	}
	csr := csrOf(t, newP256(t), "x")
	sig, err := d.ko.Sign(rand.Reader, renewMessageOf(t, d.ko, csr), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.iss.Renew(RenewRequest{Cert: der, CSR: csr, Sig: sig}, t0.Add(time.Hour)); err != nil {
		t.Fatalf("P-256 renewal: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enrol(t, device{d.kr, p384}, nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("a P-384 key: %v, want refused", err)
	}
}

// A rule's groups are within the issuer's policy, its issuer https (or
// loopback), and a removed rule enrols nothing.
func TestSignInRules(t *testing.T) {
	s := newSignInOrg(t, "alice@example.com")
	for what, r := range map[string]SignInRule{
		"group outside policy": {ID: "x", Issuer: "https://idp.example", ClientIDs: []string{"c"}, App: "send", Groups: []string{"ops"}},
		"plain http":           {ID: "x", Issuer: "http://idp.example", ClientIDs: []string{"c"}, App: "send", Groups: []string{"web"}},
		"no client":            {ID: "x", Issuer: "https://idp.example", App: "send", Groups: []string{"web"}},
		"bad app":              {ID: "x", Issuer: "https://idp.example", ClientIDs: []string{"c"}, App: "Send", Groups: []string{"web"}},
	} {
		if err := s.iss.AddSignInRule(r, t0); err == nil {
			t.Errorf("%s: added", what)
		}
	}
	if err := s.iss.RemoveSignInRule("people", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enrol(t, newDevice(t), nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("a removed rule: %v, want refused", err)
	}
}
