// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relaytrust_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/nfltr/relay/client/relaytrust"
	"github.com/nfltr/relay/client/relaytrust/relaytrusttest"
)

// TestWithPinCertificateMatrix dials a loopback server per certificate kind
// with the relay TLS config every pinned path builds (grpcclient,
// grpcfactory, relayoutage.ShareClient, the default HTTP transport after
// Install): refused unless the CA is trusted or the certificate pinned, and
// the refusal says how to fix it.
func TestWithPinCertificateMatrix(t *testing.T) {
	set := relaytrusttest.New(t)
	noRoots := x509.NewCertPool() // a hermetic stand-in for system roots
	otherPin := strings.Repeat("ab", 32)
	for _, k := range set.Kinds {
		srv := relaytrusttest.Serve(t, k.Cert)
		fp := relaytrust.Fingerprint(k.Cert.Leaf.Raw)
		modes := []struct {
			name   string
			cfg    *tls.Config
			accept bool
			hint   string // in the refusal
		}{
			{"untrusted", relaytrust.WithPin(&tls.Config{RootCAs: noRoots}, ""), false, "--cert-sha256 " + fp},
			{"CA trusted", relaytrust.WithPin(&tls.Config{RootCAs: set.CA}, ""), !k.Bad, ""},
			{"pinned", relaytrust.WithPin(&tls.Config{RootCAs: noRoots}, fp), true, ""},
			{"CA trusted, other pin", relaytrust.WithPin(&tls.Config{RootCAs: set.CA}, otherPin), !k.Bad, "is not the pinned relay certificate"},
		}
		for _, m := range modes {
			cfg := m.cfg.Clone()
			cfg.ServerName = relaytrusttest.Host
			conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), cfg)
			if err == nil {
				_ = conn.Close()
			}
			err = relaytrust.Explain(err)
			if (err == nil) != m.accept {
				t.Errorf("%s / %s: err=%v, want accepted=%v", k.Name, m.name, err, m.accept)
				continue
			}
			if err != nil {
				want := m.hint
				if want == "" {
					want = "--cert-sha256"
				}
				if k.Name == "expired" {
					want = "renew it on the relay"
				}
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s / %s: refusal %q does not say %q", k.Name, m.name, err, want)
				}
			}
			t.Logf("%-18s %-22s accepted=%v %v", k.Name, m.name, err == nil, err)
		}
	}
}

// TestPinnedIPTargetRefusalNamesTheFix: an IP address target (no SNI) with a
// pin accepts only the pinned certificate; the refusal says how to pin.
func TestPinnedIPTargetRefusalNamesTheFix(t *testing.T) {
	set := relaytrusttest.New(t)
	srv := relaytrusttest.Serve(t, set.Kinds[0].Cert)
	_, err := tls.Dial("tcp", srv.Listener.Addr().String(), relaytrust.WithPin(&tls.Config{RootCAs: set.CA}, strings.Repeat("ab", 32)))
	if err == nil || !strings.Contains(err.Error(), "nfltr config set-relay") {
		t.Fatalf("err = %v, want a refusal naming nfltr config set-relay", err)
	}
}

// TestExplainLeavesOtherErrors: only certificate refusals get the hint.
func TestExplainLeavesOtherErrors(t *testing.T) {
	plain := &net.OpError{Op: "dial"}
	if got := relaytrust.Explain(plain); got != error(plain) {
		t.Fatalf("Explain changed a non-certificate error: %v", got)
	}
	if relaytrust.Explain(nil) != nil {
		t.Fatal("Explain(nil) != nil")
	}
}

// TestGoRefusesRSAKeysBelow1024Bits records the platform floor that makes
// RSA-1024 the weakest key the matrix can present.
func TestGoRefusesRSAKeysBelow1024Bits(t *testing.T) {
	if _, err := rsa.GenerateKey(rand.Reader, 512); err == nil {
		t.Fatal("rsa.GenerateKey(512) succeeded: add a sub-1024-bit kind to relaytrusttest")
	}
}
