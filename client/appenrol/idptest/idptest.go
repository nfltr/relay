// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package idptest is an in-process OpenID Connect provider for tests of
// the sign-in path (appenrol.SignIn, the issuer's ID token check): the
// discovery document, a JWKS, the authorization endpoint (it signs the
// person in at once and redirects with a code), the token endpoint (PKCE
// S256 checked) and Token, which mints an ID token with any claims. Its
// tokens are ES256 JWTs; it is standard library only.
package idptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"
)

// IdP is the provider. Person is whom the authorization endpoint signs in
// (Email, verified unless Unverified); Now is its clock.
type IdP struct {
	URL        string
	Email      string
	Unverified bool
	TokLife    time.Duration
	Now        func() time.Time

	srv   *httptest.Server
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	codes map[string]grant
}

type grant struct{ clientID, redirect, nonce, challenge string }

// New starts an IdP signing in email; Close stops it.
func New(email string) *IdP {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	p := &IdP{Email: email, TokLife: time.Hour, Now: time.Now, key: key, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.srv = httptest.NewServer(mux)
	p.URL = p.srv.URL
	return p
}

// Close stops the IdP's server.
func (p *IdP) Close() { p.srv.Close() }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token",
		"jwks_uri": p.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"ES256"},
		"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"code_challenge_methods_supported": []string{"S256"},
	})
}

func (p *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	b, err := p.key.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enc := base64.RawURLEncoding.EncodeToString
	writeJSON(w, map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1", "x": enc(b[1:33]), "y": enc(b[33:]),
	}}})
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "authorization code with PKCE S256 only", http.StatusBadRequest)
		return
	}
	code := rand.Text()
	p.mu.Lock()
	p.codes[code] = grant{q.Get("client_id"), q.Get("redirect_uri"), q.Get("nonce"), q.Get("code_challenge")}
	p.mu.Unlock()
	to, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v := to.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	to.RawQuery = v.Encode()
	// nosemgrep: open-redirect -- a test IdP: it sends the browser to the client's redirect_uri, as an IdP does
	http.Redirect(w, r, to.String(), http.StatusFound) // #nosec G710 -- as above
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	code := r.PostFormValue("code")
	p.mu.Lock()
	g, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !ok || r.PostFormValue("grant_type") != "authorization_code" || r.PostFormValue("client_id") != g.clientID ||
		r.PostFormValue("redirect_uri") != g.redirect || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	writeJSON(w, map[string]any{"access_token": rand.Text(), "token_type": "Bearer", "expires_in": 3600,
		"id_token": p.Token(p.Claims(g.clientID, g.nonce))})
}

// Claims are the claims the IdP puts in an ID token for its person.
func (p *IdP) Claims(clientID, nonce string) map[string]any {
	now := p.Now()
	return map[string]any{"iss": p.URL, "sub": "sub-" + p.Email, "aud": clientID, "nonce": nonce,
		"email": p.Email, "email_verified": !p.Unverified, "iat": now.Unix(), "exp": now.Add(p.TokLife).Unix()}
}

// Token signs claims as an ID token of the IdP.
func (p *IdP) Token(claims map[string]any) string {
	return SignWith(p.key, claims)
}

// SignWith signs claims as an ES256 JWT under key (kid k1): another key's
// token, for a test of the signature check.
func SignWith(key *ecdsa.PrivateKey, claims map[string]any) string {
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "k1"})
	c, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	in := enc(h) + "." + enc(c)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + enc(sig)
}
