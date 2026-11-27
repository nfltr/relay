// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/client/machinecert"
	"github.com/nfltr/relay/client/relaytrust"
)

// relay-server spec/MachineAuth.tla KeptConnValid (lane ISSUERKEEP, the
// organisation issuer's outage of 2026-11-22): a long-lived process keeps
// its HTTP/2 connection to the relay, which checks the certificate the
// handshake presented at each request. The connection must close when that
// certificate expires, so the next call's handshake renews and presents a
// valid one; before, every call after the expiry was refused (403) until
// the process restarted.
func TestKeptConnectionPresentsTheRenewedCertificate(t *testing.T) {
	var key *ecdsa.PrivateKey
	renewals := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != machinecert.ReissuePath {
			http.NotFound(w, r)
			return
		}
		now := time.Now()
		_ = json.NewEncoder(w).Encode(map[string]any{"machine_id": "m-aaaa", "chain": certPEM(t, key, now.Add(-time.Minute), now.Add(time.Hour)), "not_after": now.Add(time.Hour)})
	}))
	t.Cleanup(renewals.Close)

	var dials atomic.Int32
	relay := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// the relay's authMiddleware: the presented certificate at now
		if len(r.TLS.PeerCertificates) == 0 || !time.Now().Before(r.TLS.PeerCertificates[0].NotAfter) {
			http.Error(w, "invalid credential", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, r.Proto)
	}))
	relay.EnableHTTP2 = true
	relay.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	relay.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			dials.Add(1)
		}
	}
	relay.StartTLS()
	t.Cleanup(relay.Close)
	t.Setenv(relaytrust.PinEnv, relaytrust.Fingerprint(relay.Certificate().Raw))

	dir := t.TempDir()
	key, _ = machinecert.NewKey()
	if err := machinecert.SaveKey(machinecert.KeyPath(dir), key); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := machinecert.ParseCert([]byte(certPEM(t, key, now.Add(-time.Minute), now.Add(2*time.Second))))
	if err != nil {
		t.Fatal(err)
	}
	cert.MachineID = "m-aaaa"
	if err := (&machinecert.Saved{Cert: *cert, RelayHost: "127.0.0.1", BaseURL: renewals.URL}).Store(dir); err != nil {
		t.Fatal(err)
	}
	c := load(dir)
	client := c.HTTPClient() // no Run: the handshake's renewal alone (nfltr org serve before lane ISSUERKEEP)

	call := func() (int, string) {
		resp, err := client.Get(relay.URL + "/mailbox")
		if err != nil {
			return 0, err.Error() // a connection closed under a call in flight: the caller retries
		}
		defer resp.Body.Close() //nolint:errcheck
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := call(); code != http.StatusOK || body != "HTTP/2.0" {
		t.Fatalf("first call: %d %q, want 200 over HTTP/2", code, body)
	}
	// Calls on the kept connection until a second past the certificate's
	// NotAfter (x509 keeps whole seconds), then one more: it is answered.
	for until := cert.NotAfter.Add(time.Second); time.Now().Before(until); time.Sleep(50 * time.Millisecond) {
		call()
	}
	if code, body := call(); code != http.StatusOK {
		t.Fatalf("a call after the certificate's expiry: %d %q, want 200 (the kept connection still presents the expired certificate)", code, body)
	}
	if n := dials.Load(); n < 2 {
		t.Fatalf("%d connections, want a new one after the expiry", n)
	}
}

// relay-server spec/MachineAuth.tla Refused: past a final refusal of the
// renewal the expired certificate is presented so the relay's refusal
// comes back and the command ends with ErrRefused. A connection presenting
// a certificate already past its end gets no close timer (it would fire at
// once and the caller would see "use of closed network connection", not
// the relay's 401: nfltr train cb155dfba, TestCertsSeamless "past the
// 90-day grace" exit 5, want 2).
func TestExpiredCertificateConnectionCarriesTheRelaysRefusal(t *testing.T) {
	c, _ := expiredCredential(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "machine_revoked", http.StatusUnauthorized)
	})
	relay := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid credential", http.StatusUnauthorized)
	}))
	relay.EnableHTTP2 = true
	relay.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	relay.StartTLS()
	t.Cleanup(relay.Close)
	t.Setenv(relaytrust.PinEnv, relaytrust.Fingerprint(relay.Certificate().Raw))

	resp, err := c.HTTPClient().Get(relay.URL + "/api/v1/presence/agents")
	if err != nil {
		t.Fatalf("call with the refused, expired certificate: %v, want the relay's 401", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !errors.Is(c.Refusal(errors.New("401")), ErrRefused) {
		t.Fatalf("status %d, want 401 and the machine refused", resp.StatusCode)
	}
}
