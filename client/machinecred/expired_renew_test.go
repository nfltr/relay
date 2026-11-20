// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/nfltr/relay/client/machinecert"
)

// certPEM is a machine certificate of key valid from nb to na.
func certPEM(t *testing.T, key *ecdsa.PrivateKey, nb, na time.Time) string {
	t.Helper()
	u, _ := url.Parse("spiffe://nfltr.xyz/m/m-aaaa")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(nb.Unix()), NotBefore: nb, NotAfter: na, URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// expiredCredential is a credential whose certificate expired 30 days ago
// (the machine was off), its relay's reissue route answer.
func expiredCredential(t *testing.T, answer http.HandlerFunc) (*Credential, *ecdsa.PrivateKey) {
	t.Helper()
	relay := httptest.NewServer(answer)
	t.Cleanup(relay.Close)
	dir := t.TempDir()
	key, _ := machinecert.NewKey()
	if err := machinecert.SaveKey(machinecert.KeyPath(dir), key); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-31 * 24 * time.Hour)
	cert, err := machinecert.ParseCert([]byte(certPEM(t, key, old, old.Add(24*time.Hour))))
	if err != nil {
		t.Fatal(err)
	}
	cert.MachineID = "m-aaaa"
	if err := (&machinecert.Saved{Cert: *cert, RelayHost: "127.0.0.1", BaseURL: relay.URL}).Store(dir); err != nil {
		t.Fatal(err)
	}
	return load(dir), key
}

// relay-server spec/MachineAuth.tla BackAfterExpiry, Refused (lane
// SEAMLESS): a machine off for 30 days connects again with no user action:
// the handshake renews its expired certificate with its key first and
// presents the new one; nothing was presented expired.
func TestExpiredCertificateRenewsBeforeTheHandshake(t *testing.T) {
	var key *ecdsa.PrivateKey
	c, k := expiredCredential(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != machinecert.ReissuePath {
			http.NotFound(w, r)
			return
		}
		now := time.Now()
		_ = json.NewEncoder(w).Encode(map[string]any{"machine_id": "m-aaaa", "chain": certPEM(t, key, now, now.Add(24*time.Hour)), "not_after": now.Add(24 * time.Hour)})
	})
	key = k
	got, err := c.TLSConfig(nil).GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("handshake certificate: %v", err)
	}
	if !time.Now().Before(got.Leaf.NotAfter) {
		t.Fatalf("presented a certificate that expired at %v", got.Leaf.NotAfter)
	}
	if c.Refusal(errors.New("x")) != nil && errors.Is(c.Refusal(errors.New("x")), ErrRefused) {
		t.Fatal("the credential is marked refused")
	}
}

// While the relay does not answer, an expired certificate is not
// presented: the handshake fails with ErrRenewing (a network error; the
// caller redials, nothing to do). A revoked machine's renewal (401) marks
// it refused: the expired certificate is presented, the relay refuses it,
// and the command ends with ErrRefused (one command: nfltr config login).
func TestExpiredCertificateWhileTheRelayIsDownOrRefuses(t *testing.T) {
	status := http.StatusBadGateway
	c, _ := expiredCredential(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "machine_revoked", status)
	})
	cfg := c.TLSConfig(nil)
	if _, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{}); !errors.Is(err, ErrRenewing) {
		t.Fatalf("relay down: %v, want ErrRenewing", err)
	}
	if errors.Is(c.Refusal(errors.New("dial")), ErrRefused) {
		t.Fatal("a relay that does not answer marked the machine refused")
	}
	status = http.StatusUnauthorized
	got, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil || got == nil {
		t.Fatalf("revoked: %v, want the expired certificate presented", err)
	}
	if !errors.Is(c.Refusal(errors.New("dial")), ErrRefused) {
		t.Fatal("a final refusal did not mark the machine refused")
	}
}
