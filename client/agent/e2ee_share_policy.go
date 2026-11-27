// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// sharePolicyHeader is the ConnectTCP request metadata in which an agent
// names each share whose credential policy it enforces on E2EE sessions
// (relay tcpSharePolicyHeader). The relay forwards a share with Basic Auth,
// a Bearer token or required headers only to a stream that names it.
const sharePolicyHeader = "x-nfltr-share-policy"

// SharePolicy is the credential part of a share's access policy, as the
// relay returned it to the agent that issued the share (POST /api/v1/share).
// The relay checks the share's IP allowlist itself; it cannot read E2EE
// requests, so the agent checks these.
type SharePolicy struct {
	BasicAuth       string            // "user:password"
	BearerToken     string            // "Authorization: Bearer <token>"
	RequiredHeaders map[string]string // header name -> exact value
}

// RequireSharePolicy makes every request through the E2EE sessions satisfy
// the policy of share code, checked like the relay checks it on the
// inspectable path: required headers (403), Bearer token, Basic Auth (401
// with a challenge). Nothing reaches the backend on a failure, and sessions
// take the HTTP path. The agent then names code on its ConnectTCP streams,
// so call it before RunTCPTunnel. The policy is checked for every session,
// whatever host name the client asked for. Secrets are kept as SHA-256
// digests and compared in constant time. An invalid policy is an error and
// installs nothing.
func (s *E2EESetup) RequireSharePolicy(code string, p SharePolicy) error {
	check, err := newSharePolicyCheck(code, p)
	if err != nil {
		return err
	}
	s.cfg.addWrap(check.wrap)
	s.cfg.shareCodes = append(s.cfg.shareCodes, code)
	return nil
}

// newSharePolicyCheck validates share code's policy p and returns its check.
func newSharePolicyCheck(code string, p SharePolicy) (sharePolicyCheck, error) {
	if err := validateSharePolicy(code, p); err != nil {
		return sharePolicyCheck{}, err
	}
	check := sharePolicyCheck{
		basic:   digestOf(p.BasicAuth),
		bearer:  digestOf(p.BearerToken),
		headers: make(map[string][sha256.Size]byte, len(p.RequiredHeaders)),
	}
	for name, value := range p.RequiredHeaders {
		check.headers[http.CanonicalHeaderKey(name)] = sha256.Sum256([]byte(value))
	}
	return check, nil
}

func validateSharePolicy(code string, p SharePolicy) error {
	if !validShareCode(code) {
		return fmt.Errorf("share policy: invalid share code %q", code)
	}
	if p.BasicAuth == "" && p.BearerToken == "" && len(p.RequiredHeaders) == 0 {
		return errors.New("share policy: no Basic Auth, Bearer token or required header to enforce")
	}
	if p.BasicAuth != "" && !strings.Contains(p.BasicAuth, ":") {
		return errors.New("share policy: Basic Auth must be user:password")
	}
	if p.BearerToken != "" && !httpguts.ValidHeaderFieldValue(p.BearerToken) {
		return errors.New("share policy: invalid Bearer token")
	}
	for name, value := range p.RequiredHeaders {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("share policy: invalid required header %q", name)
		}
	}
	return nil
}

// validShareCode: a share code is a host label of lowercase letters,
// digits and inner hyphens (relay looksLikeShareCode).
func validShareCode(code string) bool {
	if code == "" || len(code) > 63 || code[0] == '-' || code[len(code)-1] == '-' {
		return false
	}
	for _, c := range code {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

type sharePolicyCheck struct {
	basic, bearer *[sha256.Size]byte // nil: not required
	headers       map[string][sha256.Size]byte
}

func digestOf(secret string) *[sha256.Size]byte {
	if secret == "" {
		return nil
	}
	d := sha256.Sum256([]byte(secret))
	return &d
}

func matchesDigest(want [sha256.Size]byte, presented string) bool {
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// wrap checks c before next, in the relay's order (enforceSharePolicy).
// allow:wrapper
func (c sharePolicyCheck) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, want := range c.headers {
			if !matchesDigest(want, r.Header.Get(name)) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		if c.bearer != nil {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || !matchesDigest(*c.bearer, token) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="nfltr"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		if c.basic != nil {
			user, pass, ok := r.BasicAuth()
			if !ok || !matchesDigest(*c.basic, user+":"+pass) {
				w.Header().Set("WWW-Authenticate", `Basic realm="nfltr"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		if c.basic != nil || c.bearer != nil {
			// The share's credential, checked here, as the relay strips it
			// on a share it checks: not the service's.
			r.Header.Del("Authorization")
		}
		next.ServeHTTP(w, r)
	})
}
