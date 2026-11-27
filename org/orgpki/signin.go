// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/nfltr/relay/client/appenrol"
	"github.com/nfltr/relay/client/orgid"
)

// AuthLife is how long a person's sign-in lets the key it enrolled renew
// by itself (spec/appenrol/AppEnrol.tla; nfltr
// docs/decisions/app-device-identity-2026-11-16.md, open question 1:
// 30 days). Then the person signs in again on the device (EnrolSignIn
// with the same key).
const AuthLife = 30 * 24 * time.Hour

// ErrSignInEnded: a key enrolled by sign-in asked to renew after its
// sign-in ended (AuthLife); the person signs in again on the device.
var ErrSignInEnded = errors.New("the sign-in ended: sign in again on this device")

// SignInRule is the owner's rule for sign-in: ID tokens of Issuer for
// one of ClientIDs (the app's clients at the IdP) authenticate a device of
// App for the token's verified email, in Groups. A sign-in enrols a new
// key only with an invite for that email (people.go; owner decision
// 2026-11-25: invites only, no domain rules).
type SignInRule struct {
	ID        string   `json:"id"`
	Issuer    string   `json:"issuer"`
	ClientIDs []string `json:"client_ids"`
	App       string   `json:"app"`
	Groups    []string `json:"groups"`
}

// SignInRequest is a device's enrolment by sign-in: the ID token, the rule
// it is for, the CSR of its organisation key and its relay key (PKIX);
// the token's nonce names both keys (appenrol.Nonce). A join (a key not
// enrolled) carries its invite's proof (ProveInvite).
type SignInRequest struct {
	Rule     string       `json:"rule"`
	IDToken  string       `json:"id_token"`
	CSR      []byte       `json:"csr"`
	RelayKey []byte       `json:"relay_key"`
	Invite   *InviteProof `json:"invite,omitempty"`
}

// NewSignInRequest is the device's side: relayKey's SPKI beside the rest.
func NewSignInRequest(rule, idToken string, csr []byte, relayKey crypto.PublicKey) (SignInRequest, error) {
	spki, err := x509.MarshalPKIXPublicKey(relayKey)
	if err != nil {
		return SignInRequest{}, err
	}
	return SignInRequest{Rule: rule, IDToken: idToken, CSR: csr, RelayKey: spki}, nil
}

func (r SignInRule) valid() (SignInRule, error) {
	if err := ValidLabel("rule id", r.ID); err != nil {
		return r, err
	}
	if err := ValidLabel("app", r.App); err != nil {
		return r, err
	}
	if err := validGroups(r.Groups); err != nil {
		return r, err
	}
	u, err := url.Parse(r.Issuer)
	if err != nil || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && loopback(u.Hostname())) {
		return r, fmt.Errorf("issuer %q: an https URL", r.Issuer)
	}
	if len(r.ClientIDs) == 0 || slices.Contains(r.ClientIDs, "") {
		return r, errors.New("at least one client id")
	}
	return r, nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// AddSignInRule adds (or replaces) a rule; its groups must be in the
// issuer's policy.
func (i *Issuer) AddSignInRule(r SignInRule, now time.Time) error {
	r.ClientIDs, r.Groups = slices.Clone(r.ClientIDs), slices.Clone(r.Groups)
	r, err := r.valid()
	if err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !subset(r.Groups, i.Groups()) {
		return fmt.Errorf("%w: groups %v are not all in the issuer's policy %v", ErrRefused, r.Groups, i.Groups())
	}
	return i.commit(Entry{Time: now, Act: ActRule, Rule: &r})
}

// RemoveSignInRule removes rule id: it enrols no device from now; devices
// it enrolled renew until their sign-in ends.
func (i *Issuer) RemoveSignInRule(id string, now time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, ok := i.rules[id]; !ok {
		return fmt.Errorf("no sign-in rule %q", id)
	}
	return i.commit(Entry{Time: now, Act: ActRuleRemoved, Name: id})
}

// SignInRules are the issuer's rules, by id.
func (i *Issuer) SignInRules() []SignInRule {
	i.mu.Lock()
	defer i.mu.Unlock()
	var rs []SignInRule
	for _, r := range i.rules {
		rs = append(rs, r)
	}
	slices.SortFunc(rs, func(a, b SignInRule) int { return strings.Compare(a.ID, b.ID) })
	return rs
}

// signIn is what a verified ID token says, as the log records it.
type signIn struct {
	idp, sub, email, clientID, nonce string
	exp                              time.Time
}

// idpWait bounds a sign-in's ID token check (the IdP's discovery and keys):
// the issuer decides under its directory's lock.
const idpWait = 30 * time.Second

// providers caches each IdP's discovery and keys (go-oidc refreshes the
// keys on an unknown kid).
type providers struct {
	mu sync.Mutex
	by map[string]*oidc.Provider
}

func (p *providers) get(ctx context.Context, issuer string) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pr := p.by[issuer]; pr != nil {
		return pr, nil
	}
	// The client bounds every request to the IdP, the key fetches go-oidc
	// runs later included (they keep this context's values).
	pr, err := oidc.NewProvider(oidc.ClientContext(ctx, &http.Client{Timeout: idpWait}), issuer)
	if err != nil {
		return nil, err
	}
	if p.by == nil {
		p.by = map[string]*oidc.Provider{}
	}
	p.by[issuer] = pr
	return pr, nil
}

// verifyIDToken checks raw as rule's: the IdP's signature over its keys,
// iss, exp at now (go-oidc), aud (and azp) among the rule's client ids, a
// verified email.
func (i *Issuer) verifyIDToken(ctx context.Context, rule SignInRule, raw string, now time.Time) (signIn, error) {
	p, err := i.idps.get(ctx, rule.Issuer)
	if err != nil {
		return signIn{}, err
	}
	t, err := p.VerifierContext(ctx, &oidc.Config{SkipClientIDCheck: true, Now: func() time.Time { return now }}).Verify(ctx, raw)
	if err != nil {
		return signIn{}, err
	}
	var c struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
		AZP      string `json:"azp"`
	}
	if err := t.Claims(&c); err != nil {
		return signIn{}, err
	}
	client := ""
	for _, a := range t.Audience {
		if slices.Contains(rule.ClientIDs, a) {
			client = a
		}
	}
	switch {
	case client == "" || c.AZP != "" && !slices.Contains(rule.ClientIDs, c.AZP):
		return signIn{}, fmt.Errorf("the token is for %v, not a client of rule %s", t.Audience, rule.ID)
	case !c.Verified:
		return signIn{}, errors.New("the token's email is not verified")
	}
	return signIn{idp: t.Issuer, sub: t.Subject, email: c.Email, clientID: client, nonce: t.Nonce, exp: t.Expiry}, nil
}

// EnrolSignIn enrols the key of req.CSR by a person's sign-in
// (AppEnrol.tla EnrolSSO, Reauth): the ID token verified against its rule
// (outside the issuer's lock: it may fetch the IdP's keys),
// its nonce naming the request's two keys, the person and the app not
// revoked. A key not enrolled is a join (people.go; People.tla Join): it
// needs an open invite for the token's person proved over the request's
// keys, and gets a fresh name <app>-<n> the issuer picks (never the
// request's), the token's person, the rule's app and groups and the
// invite's role. A key the person enrolled by sign-in for that app is certified
// again (a sign-in again, or an answer lost) and renews by itself
// AuthLife on; any other enrolled key is refused.
func (i *Issuer) EnrolSignIn(ctx context.Context, req SignInRequest, now time.Time) ([]byte, error) {
	i.mu.Lock()
	rule, ok := i.rules[req.Rule]
	i.mu.Unlock()
	var si signIn
	var verr error
	if ok {
		vctx, cancel := context.WithTimeout(ctx, idpWait)
		si, verr = i.verifyIDToken(vctx, rule, req.IDToken, now)
		cancel()
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	var kr crypto.PublicKey
	tr := func(ev, name, why string, k crypto.PublicKey) { // spec/appenrol/TraceAppEnrol.tla
		l := map[string]any{"ev": ev, "o": i.orgID, "n": name, "why": why, "u": strings.ToLower(si.email), "a": rule.App,
			"exp": si.exp.Unix(), "nonce": si.nonce, "au": now.Add(AuthLife).Unix(), "t": now.Unix()}
		if k != nil {
			l["k"] = orgid.KeyFingerprint(k)
			l["kn"], _ = appenrol.Nonce(kr, k)
		}
		appTraceLine(l)
	}
	refusal := Entry{Time: now}
	switch {
	case !ok:
		return nil, i.refuse(refusal, "no sign-in rule "+req.Rule)
	case verr != nil:
		tr("refuse", "", "token", nil)
		return nil, i.refuse(refusal, "ID token: "+verr.Error())
	}
	refusal.Person, refusal.App, refusal.IdP, refusal.Subject = si.email, rule.App, si.idp, si.sub
	cr, err := parseCSR(req.CSR)
	if err != nil {
		return nil, i.refuse(refusal, "CSR: "+err.Error())
	}
	kr, err = x509.ParsePKIXPublicKey(req.RelayKey)
	if err != nil {
		return nil, i.refuse(refusal, "relay key: "+err.Error())
	}
	pub := cr.PublicKey
	if err := appenrol.CheckNonce(si.nonce, kr, pub); err != nil {
		tr("refuse", "", "nonce", pub)
		return nil, i.refuse(refusal, err.Error())
	}
	dev, err := Device{Person: si.email, App: rule.App}.valid()
	if err != nil {
		return nil, i.refuse(refusal, err.Error())
	}
	if i.deniedDev(dev) { // AppEnrol.tla EnrolSSO, Reauth: the deny lists
		tr("refuse", "", "denied", pub)
		return nil, i.refuse(refusal, "the person or the app is revoked")
	}
	name, groups := i.nameOfKey(pub), rule.Groups
	var inv *inviteRec
	if name != "" {
		n := i.names[name]
		refusal.Name = name
		switch {
		case n.revoked:
			tr("refuse", name, "revoked", pub)
			return nil, i.refuse(refusal, name+" is revoked")
		case n.authUntil.IsZero():
			tr("refuse", name, "code", pub)
			return nil, i.refuse(refusal, name+" was enrolled by a code, not a sign-in")
		case n.dev != dev: // AppEnrol.tla Reauth (mutant reauth-any-user)
			tr("refuse", name, "other", pub)
			return nil, i.refuse(refusal, name+" is another person's or app's")
		}
		groups = n.groups
	} else {
		// A new key is a join (People.tla Join, JoinNeedsInvite): the
		// person's invite, its role (BIND:people.invite, people.role).
		var why string
		if inv, why = i.checkInvite(req, dev.Person, now); why != "" {
			tr("refuse", "", "invite", pub)
			return nil, i.refuse(refusal, why)
		}
		if name = i.freeName(rule.App); name == "" {
			return nil, i.refuse(refusal, "no free name for app "+rule.App)
		}
	}
	refusal.Name = name
	der, err := i.issueEntry(ActIssued, name, groups, "", dev, pub, "", "", now, func(e *Entry) {
		e.IdP, e.Subject, e.ClientID, e.AuthUntil = si.idp, si.sub, si.clientID, now.Add(AuthLife)
		if inv != nil {
			e.Invite, e.Role = inviteID(req.Invite.Key), inv.role
		}
	})
	if err == nil {
		tr("sso", name, "", pub)
	}
	return der, err
}

// nameOfKey is the name whose newest certificate is for pub, "" if none.
// Callers hold mu.
func (i *Issuer) nameOfKey(pub crypto.PublicKey) string {
	fp := orgid.KeyFingerprint(pub)
	for name, n := range i.names {
		if i.certs[n.serials[len(n.serials)-1]].key == fp {
			return name
		}
	}
	return ""
}

// freeName is the first <app>-<n> neither enrolled nor a token's, "" past
// a DNS label's length. Callers hold mu.
func (i *Issuer) freeName(app string) string {
	taken := map[string]bool{}
	for _, t := range i.tokens {
		taken[t.name] = true
	}
	for k := 1; ; k++ {
		name := fmt.Sprintf("%s-%d", app, k)
		if ValidLabel("name", name) != nil {
			return ""
		}
		if i.names[name] == nil && !taken[name] {
			return name
		}
	}
}
