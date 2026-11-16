// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package appenrol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/appenrol/idptest"
)

// TestSignInTokenNamesTheDevicesKeys: SignIn runs the code flow with PKCE
// against the IdP stand-in (the person's browser follows the redirects)
// and returns an ID token for the client whose nonce names the device's
// two keys.
func TestSignInTokenNamesTheDevicesKeys(t *testing.T) {
	idp := idptest.New("alice@example.com")
	defer idp.Close()
	kr, ko, _ := keys(t)
	var page string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := SignIn(ctx, SignInConfig{Issuer: idp.URL, ClientID: "send-desktop", RelayKey: kr, OrgKey: ko,
		Open: func(u string) error {
			if !strings.Contains(u, "code_challenge_method=S256") {
				t.Errorf("authorization URL without PKCE: %s", u)
			}
			resp, err := http.Get(u) // the browser: the IdP's redirect to the loopback callback
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			page = string(b)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page, "Signed in") {
		t.Errorf("callback page %q", page)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct{ Aud, Nonce, Email string }
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Aud != "send-desktop" || c.Email != "alice@example.com" {
		t.Errorf("claims %+v", c)
	}
	if err := CheckNonce(c.Nonce, kr, ko); err != nil {
		t.Errorf("the token's nonce: %v", err)
	}
}

// TestSignInRefusesAnotherState: a redirect to the loopback with another
// state (a page racing the sign-in) is not taken; the sign-in ends with
// its context.
func TestSignInRefusesAnotherState(t *testing.T) {
	idp := idptest.New("alice@example.com")
	defer idp.Close()
	kr, ko, _ := keys(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := SignIn(ctx, SignInConfig{Issuer: idp.URL, ClientID: "c", RelayKey: kr, OrgKey: ko,
		Open: func(u string) error {
			au, err := url.Parse(u)
			if err != nil {
				return err
			}
			resp, err := http.Get(au.Query().Get("redirect_uri") + "?code=x&state=forged")
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("forged state answered %s", resp.Status)
			}
			return nil
		}})
	if err == nil {
		t.Fatal("sign-in took a forged state")
	}
}
