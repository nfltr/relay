// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package turnwire

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // the scheme under test
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestTURNRESTCredential(t *testing.T) {
	secret := []byte("0123456789abcdef-shared")
	now := time.Unix(1_700_000_000, 500)
	user, pass, exp, err := TURNRESTCredential(secret, "acct.alice", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := "1700003600:acct.alice"; user != want {
		t.Fatalf("username = %q, want %q", user, want)
	}
	if exp.Unix() != 1_700_003_600 {
		t.Fatalf("expires = %v", exp)
	}
	mac := hmac.New(sha1.New, secret)
	mac.Write([]byte(user))
	if want := base64.StdEncoding.EncodeToString(mac.Sum(nil)); pass != want {
		t.Fatalf("password = %q, want %q", pass, want)
	}
	// A different secret gives a different password: the TURN server refuses it.
	_, other, _, _ := TURNRESTCredential([]byte("another-secret-of-16b"), "acct.alice", time.Hour, now)
	if other == pass {
		t.Fatal("password does not depend on the secret")
	}
	// ":" in the id cannot forge another expiry.
	if u, _, _, _ := TURNRESTCredential(secret, "a:9999999999", time.Hour, now); u != "1700003600:a_9999999999" {
		t.Fatalf("id not sanitised: %q", u)
	}
}

func TestTURNRESTCredentialRejects(t *testing.T) {
	now := time.Now()
	good := []byte("0123456789abcdef")
	for name, tc := range map[string]struct {
		secret []byte
		id     string
		ttl    time.Duration
	}{
		"short secret":  {[]byte("short"), "a", time.Hour},
		"ttl too short": {good, "a", time.Second},
		"ttl too long":  {good, "a", 25 * time.Hour},
		"empty id":      {good, " ", time.Hour},
		"control id":    {good, "a\nb", time.Hour},
	} {
		if _, _, _, err := TURNRESTCredential(tc.secret, tc.id, tc.ttl, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateTURNURL(t *testing.T) {
	for _, ok := range []string{
		"turn:turn.example.com", "turn:10.99.0.3:3478?transport=udp", "turns:turn.example.com:5349?transport=tcp",
		"turn:[2001:db8::1]:3478",
	} {
		if err := ValidateTURNURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "stun:x:3478", "http://x", "turn:", "turn://x:3478", "turn:user@x", "turn:x:0", "turn:x:70000",
		"turn:x?transport=sctp", "turn:x?foo=1", "turn:x#f", "turn:a b", "turn:x\"y", "turn:2001:db8::1",
		"turn:" + strings.Repeat("a", 600),
	} {
		if err := ValidateTURNURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidateICEServers(t *testing.T) {
	good := ICEServer{URLs: []string{"turn:x:3478"}, Username: "1:a", Credential: "c"}
	if err := ValidateICEServers(nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateICEServers([]ICEServer{good}); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]ICEServer{
		"no urls":       {Username: "u", Credential: "c"},
		"stun url":      {URLs: []string{"stun:x"}, Username: "u", Credential: "c"},
		"no username":   {URLs: good.URLs, Credential: "c"},
		"no credential": {URLs: good.URLs, Username: "u"},
		"control chars": {URLs: good.URLs, Username: "u\x00", Credential: "c"},
	} {
		if err := ValidateICEServers([]ICEServer{s}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	many := make([]ICEServer, maxICEServers+1)
	for i := range many {
		many[i] = good
	}
	if err := ValidateICEServers(many); err == nil {
		t.Error("unbounded list accepted")
	}
}
