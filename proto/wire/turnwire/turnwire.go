// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package turnwire

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is what the TURN REST API scheme (and coturn's use-auth-secret) verifies.
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ICEServer is one RTCIceServer entry handed to the call page: TURN URLs plus
// the credential the browser presents to the TURN server.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// TURN credential bounds. A TURN server rechecks the credential on every
// allocation refresh, so a call outlives its TURN path once the TTL passes.
const (
	MinTURNCredentialTTL = time.Minute
	MaxTURNCredentialTTL = 24 * time.Hour

	maxICEServers    = 8
	maxTURNURLs      = 8
	maxTURNFieldSize = 512
	// minTURNSecretLen keeps a guessable shared secret out of the relay.
	minTURNSecretLen = 16
)

// TURNRESTCredential issues a short-lived TURN credential in the TURN REST API
// scheme (draft-uberti-behave-turn-rest-00, coturn `use-auth-secret`):
// username = "<unix expiry>:<id>", password = base64(HMAC-SHA1(secret,
// username)). The TURN server holding the same secret verifies it statelessly
// and refuses it after the expiry.
func TURNRESTCredential(secret []byte, id string, ttl time.Duration, now time.Time) (username, password string, expires time.Time, err error) {
	if len(secret) < minTURNSecretLen {
		return "", "", time.Time{}, fmt.Errorf("turn: shared secret shorter than %d bytes", minTURNSecretLen)
	}
	if ttl < MinTURNCredentialTTL || ttl > MaxTURNCredentialTTL {
		return "", "", time.Time{}, fmt.Errorf("turn: credential ttl %s outside [%s, %s]", ttl, MinTURNCredentialTTL, MaxTURNCredentialTTL)
	}
	// ":" separates expiry from id; keep the id to one opaque token.
	id = strings.ReplaceAll(strings.TrimSpace(id), ":", "_")
	if id == "" || len(id) > 128 || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return "", "", time.Time{}, errors.New("turn: credential id must be 1-128 printable characters")
	}
	expires = now.Add(ttl).Truncate(time.Second)
	username = strconv.FormatInt(expires.Unix(), 10) + ":" + id
	mac := hmac.New(sha1.New, secret)
	mac.Write([]byte(username))
	return username, base64.StdEncoding.EncodeToString(mac.Sum(nil)), expires, nil
}

// ValidateTURNSecret checks an operator-supplied TURN shared secret.
func ValidateTURNSecret(secret string) error {
	if len(secret) < minTURNSecretLen {
		return fmt.Errorf("turn: shared secret must be at least %d bytes", minTURNSecretLen)
	}
	return nil
}

// ValidateTURNURL accepts an RFC 7065 TURN URI: turn:|turns: host[:port]
// with an optional ?transport=udp|tcp and nothing else.
func ValidateTURNURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "turn" && u.Scheme != "turns") || u.Opaque == "" || u.Fragment != "" {
		return fmt.Errorf("turn: %q is not a turn:/turns: URL (turn:host[:port][?transport=udp|tcp])", raw)
	}
	if len(raw) > maxTURNFieldSize || strings.ContainsAny(u.Opaque, "/@ ") {
		return fmt.Errorf("turn: invalid host in %q", raw)
	}
	host, port, splitErr := net.SplitHostPort(u.Opaque)
	if splitErr != nil {
		host, port = u.Opaque, ""
		if strings.Contains(host, ":") {
			return fmt.Errorf("turn: invalid host in %q", raw)
		}
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("turn: invalid port in %q", raw)
		}
	}
	if host == "" || (net.ParseIP(host) == nil && strings.Trim(host, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != "") {
		return fmt.Errorf("turn: invalid host in %q", raw)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("turn: invalid query in %q", raw)
	}
	for k, v := range q {
		if k != "transport" || len(v) != 1 || (v[0] != "udp" && v[0] != "tcp") {
			return fmt.Errorf("turn: %q: only ?transport=udp|tcp is allowed", raw)
		}
	}
	return nil
}

// ValidateICEServers checks TURN servers before they reach a call page: a
// bounded list of TURN URLs, each entry with a username and credential.
func ValidateICEServers(servers []ICEServer) error {
	if len(servers) > maxICEServers {
		return fmt.Errorf("turn: %d ICE servers, at most %d", len(servers), maxICEServers)
	}
	for _, s := range servers {
		if len(s.URLs) == 0 || len(s.URLs) > maxTURNURLs {
			return fmt.Errorf("turn: an ICE server needs 1-%d URLs", maxTURNURLs)
		}
		for _, u := range s.URLs {
			if err := ValidateTURNURL(u); err != nil {
				return err
			}
		}
		for name, v := range map[string]string{"username": s.Username, "credential": s.Credential} {
			if v == "" || len(v) > maxTURNFieldSize || strings.IndexFunc(v, unicode.IsControl) >= 0 {
				return fmt.Errorf("turn: %s must be 1-%d printable characters", name, maxTURNFieldSize)
			}
		}
	}
	return nil
}
