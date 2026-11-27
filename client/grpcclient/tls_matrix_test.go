// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/relaytrust"
	"github.com/nfltr/relay/client/relaytrust/relaytrusttest"
)

// TestDialConnCertificateMatrix dials a loopback relay per certificate
// kind on a TCP tunnel's data connection path: the relay config (system
// roots, the PinEnv pin) refuses every unpinned test certificate with a
// hint, accepts a pinned one; an explicit config with the test CA (the mTLS
// path) accepts only the good kinds and gets no pin hint (it ignores pins).
func TestDialConnCertificateMatrix(t *testing.T) {
	set := relaytrusttest.New(t)
	for _, k := range set.Kinds {
		srv := relaytrusttest.Serve(t, k.Cert)
		_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(p)
		fp := relaytrust.Fingerprint(k.Cert.Leaf.Raw)
		modes := []struct {
			name   string
			pin    string
			cfg    *tls.Config
			accept bool
			hint   string
		}{
			{"untrusted", "", nil, false, "--cert-sha256 " + fp},
			{"pinned", fp, nil, true, ""},
			{"CA trusted (explicit config)", "", &tls.Config{RootCAs: set.CA}, !k.Bad, ""},
		}
		for _, m := range modes {
			t.Setenv(relaytrust.PinEnv, m.pin)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err := DialConn(ctx, true, m.cfg, relaytrusttest.Host, port)
			cancel()
			if err == nil {
				_ = conn.Close()
			}
			if (err == nil) != m.accept {
				t.Errorf("%s / %s: err=%v, want accepted=%v", k.Name, m.name, err, m.accept)
				continue
			}
			if err != nil && k.Name != "expired" && m.hint != "" && !strings.Contains(err.Error(), m.hint) {
				t.Errorf("%s / %s: refusal %q does not say %q", k.Name, m.name, err, m.hint)
			}
			if err != nil && m.cfg != nil && strings.Contains(err.Error(), "--cert-sha256") {
				t.Errorf("%s / %s: explicit config ignores pins, but the refusal suggests one: %v", k.Name, m.name, err)
			}
			t.Logf("%-18s %-28s accepted=%v %v", k.Name, m.name, err == nil, err)
		}
	}
}

// TestNewClientConnRefusalNamesTheFix: gRPC reports a refused relay
// certificate as text; it must still name the pin command.
func TestNewClientConnRefusalNamesTheFix(t *testing.T) {
	t.Setenv(relaytrust.PinEnv, "")
	set := relaytrusttest.New(t)
	srv := relaytrusttest.Serve(t, set.Kinds[2].Cert) // self-signed
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	// 127.0.0.1 (in the certificate), not Host: grpc dials each address
	// localhost resolves to and reports the last failure, which may be
	// ::1 refusing the connection rather than the TLS refusal.
	conn, err := NewClientConn(true, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = conn.Invoke(ctx, "/nfltr.test.Probe/Call", struct{}{}, new(struct{}))
	if err == nil || !strings.Contains(err.Error(), "--cert-sha256 "+relaytrust.Fingerprint(set.Kinds[2].Cert.Leaf.Raw)) {
		t.Fatalf("err = %v, want the refusal to name nfltr config set-relay --cert-sha256", err)
	}
}
