// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package relaytrust lets a client trust one self-signed relay certificate by
// its SHA-256 fingerprint (a relay you run, `nfltr relay serve
// --tls-self-signed`) without weakening verification of any other host.
//
// The pin comes from PinEnv; nfltr's main exports a saved pin there and calls
// Install, so the gRPC dialer (grpcclient.NewClientConn), Go's default HTTP
// transport and every child process (node agents, the hub's nfltr mcp) use it.
package relaytrust

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// PinEnv names the pinned relay certificate's SHA-256 fingerprint.
const PinEnv = "NFLTR_RELAY_CERT_SHA256"

// Fingerprint is the pin of a DER certificate: lowercase hex SHA-256.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ParsePin normalizes a fingerprint to Fingerprint's form and rejects
// anything that is not a SHA-256. It is the one parser of certificate pins:
// it accepts any case, optional colons and an optional "SHA256:" prefix, so
// the forms nfltr prints (`nfltr relay serve`, an agent's E2EE banner) and
// the "SHA256:AB:CD:..." form all work wherever a pin is taken.
func ParsePin(s string) (string, error) {
	pin := strings.ToLower(strings.TrimSpace(s))
	pin = strings.ReplaceAll(strings.TrimPrefix(pin, "sha256:"), ":", "")
	if b, err := hex.DecodeString(pin); err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("certificate fingerprint %q: want the 64 hex digits of a SHA-256", s)
	}
	return pin, nil
}

// WithPin returns a copy of cfg (nil: a new config) that also accepts the
// server certificate whose fingerprint is pin. Any other certificate must
// verify against cfg.RootCAs (nil: the system roots) for the server name, as
// without a pin. When the server name is not known to the verifier (an IP
// address target, which TLS does not send as SNI) only the pinned
// certificate is accepted: failing closed instead of skipping the name
// check. An empty pin returns cfg unchanged; a malformed one never matches.
func WithPin(cfg *tls.Config, pin string) *tls.Config {
	if strings.TrimSpace(pin) == "" {
		return cfg
	}
	want, _ := ParsePin(pin)
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	if cfg.InsecureSkipVerify { // an explicit opt-out stays one
		return cfg
	}
	roots := cfg.RootCAs
	// Verification moves to VerifyConnection, which does what the default
	// verifier does and accepts the pinned certificate besides.
	cfg.InsecureSkipVerify = true //nolint:gosec // VerifyConnection verifies every connection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("relaytrust: server sent no certificate")
		}
		leaf := cs.PeerCertificates[0]
		if want != "" && Fingerprint(leaf.Raw) == want {
			return nil
		}
		fp := Fingerprint(leaf.Raw)
		if cs.ServerName == "" {
			return fmt.Errorf("relaytrust: certificate %s is not the pinned relay certificate (%s)", fp, pinHint(fp))
		}
		opts := x509.VerifyOptions{Roots: roots, DNSName: cs.ServerName, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(opts); err != nil {
			return fmt.Errorf("relaytrust: certificate %s is not the pinned relay certificate and does not verify: %w (%s)", fp, err, remedy(err, fp))
		}
		return nil
	}
	return cfg
}

// Install makes this process and its children trust pin: it is exported in
// PinEnv (unless the environment already names one) and added to Go's
// default HTTP transport, which every http.Client without its own Transport
// uses. An empty pin does nothing.
func Install(pin string) {
	if strings.TrimSpace(pin) == "" {
		return
	}
	if strings.TrimSpace(os.Getenv(PinEnv)) == "" {
		_ = os.Setenv(PinEnv, pin)
	}
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t.TLSClientConfig = WithPin(t.TLSClientConfig, pin)
	}
}

// Explain adds what to do to err when it is a TLS handshake that refused
// the relay's certificate (untrusted, expired or for another name); any
// other error comes back unchanged. For connections that honour the pin
// (PinEnv, `nfltr config set-relay --cert-sha256`).
func Explain(err error) error {
	var cv *tls.CertificateVerificationError
	if !errors.As(err, &cv) || len(cv.UnverifiedCertificates) == 0 {
		return err
	}
	return fmt.Errorf("%w (%s)", err, remedy(cv.Err, Fingerprint(cv.UnverifiedCertificates[0].Raw)))
}

// remedy is what fixes err, the verification error of the certificate
// whose fingerprint is fp.
func remedy(err error, fp string) string {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return "the relay's certificate has expired or is not valid yet: renew it on the relay, or check this machine's clock"
	}
	if _, ok := errors.AsType[x509.HostnameError](err); ok {
		return "the relay's certificate is for another name: use an address it names, or " + pinHint(fp)
	}
	return "this machine does not trust the relay's certificate: if your own CA issued it, add that CA to the system trust store (SSL_CERT_FILE on Linux); or " + pinHint(fp)
}

// pinHint is how to trust the one certificate fp; shared by every refusal
// message. allow:wrapper
func pinHint(fp string) string {
	return fmt.Sprintf("if %s is the fingerprint your relay printed (`nfltr relay serve`), pin it: nfltr config set-relay <host:port> --cert-sha256 %s, or set %s", fp, fp, PinEnv)
}
