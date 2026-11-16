// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package appenrol

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// SignInConfig is a sign-in at the organisation's IdP for one device.
type SignInConfig struct {
	Issuer   string // the IdP's issuer URL (its discovery document is under it)
	ClientID string // the app's public client id at the IdP
	// RelayKey and OrgKey are the device's two keys: the ID token's nonce
	// commits to them (Nonce), so it enrols these keys only.
	RelayKey, OrgKey crypto.PublicKey
	// Open shows the person the authorization URL (a browser; a CLI may
	// print it). Required.
	Open func(url string) error
	// HTTPClient talks to the IdP (discovery, code exchange); nil is
	// http.DefaultClient.
	HTTPClient *http.Client
}

// SignIn is OpenID Connect authorization code + PKCE (RFC 7636) with a
// loopback redirect (RFC 8252 §7.3): it listens on 127.0.0.1, has Open
// show the IdP's page, takes the code the IdP redirects back with and
// exchanges it for the ID token, which it returns unverified (the issuer
// and the relay verify it). The relay is on none of these paths.
func SignIn(ctx context.Context, c SignInConfig) (idToken string, err error) {
	if c.Issuer == "" || c.ClientID == "" || c.Open == nil {
		return "", errors.New("appenrol: sign-in needs an issuer, a client id and Open")
	}
	nonce, err := Nonce(c.RelayKey, c.OrgKey)
	if err != nil {
		return "", err
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, hc)
	ep, err := discover(ctx, hc, c.Issuer)
	if err != nil {
		return "", err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("appenrol: loopback listener: %w", err)
	}
	defer ln.Close()
	cfg := oauth2.Config{ClientID: c.ClientID, Endpoint: ep, Scopes: []string{"openid", "email"},
		RedirectURL: "http://" + ln.Addr().String() + "/callback"}
	verifier, state := oauth2.GenerateVerifier(), rand.Text()
	codes := make(chan string, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/callback" || q.Get("state") != state || q.Get("code") == "" {
			http.Error(w, "not this sign-in's answer", http.StatusBadRequest)
			return
		}
		select {
		case codes <- q.Get("code"):
			_, _ = w.Write([]byte("Signed in. You can close this window.\n"))
		default:
			http.Error(w, "answered already", http.StatusConflict)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	if err := c.Open(cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))); err != nil {
		return "", err
	}
	var code string
	select {
	case code = <-codes:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", fmt.Errorf("appenrol: code exchange: %w", err)
	}
	id, _ := tok.Extra("id_token").(string)
	if id == "" {
		return "", errors.New("appenrol: the IdP answered no ID token")
	}
	return id, nil
}

// discover reads the IdP's endpoints from its discovery document (OpenID
// Connect Discovery 1.0 §4).
func discover(ctx context.Context, hc *http.Client, issuer string) (oauth2.Endpoint, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oauth2.Endpoint{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return oauth2.Endpoint{}, fmt.Errorf("appenrol: discovery: %w", err)
	}
	defer resp.Body.Close()
	var d struct {
		Issuer string `json:"issuer"`
		Auth   string `json:"authorization_endpoint"`
		Token  string `json:"token_endpoint"`
	}
	if resp.StatusCode != http.StatusOK {
		return oauth2.Endpoint{}, fmt.Errorf("appenrol: discovery: %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return oauth2.Endpoint{}, fmt.Errorf("appenrol: discovery: %w", err)
	}
	if d.Issuer != issuer || d.Auth == "" || d.Token == "" {
		return oauth2.Endpoint{}, fmt.Errorf("appenrol: discovery of %s names issuer %q", issuer, d.Issuer)
	}
	// A public client: no secret, the client id in the form.
	return oauth2.Endpoint{AuthURL: d.Auth, TokenURL: d.Token, AuthStyle: oauth2.AuthStyleInParams}, nil
}
