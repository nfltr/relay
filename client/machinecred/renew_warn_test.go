// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/machinecert"
)

// syncBuf is a log buffer the renewal goroutine writes while the test reads.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// A renewal that fails before the certificate expires is logged as a
// warning with the time left, at each attempt, so an operator sees it
// hours ahead (incident 2026-11-18: nothing was logged until two hours
// after the expiry).
func TestRenewalFailureIsLoggedWithTheTimeLeft(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer relay.Close()
	dir := t.TempDir()
	key, _ := machinecert.NewKey()
	if err := machinecert.SaveKey(machinecert.KeyPath(dir), key); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("spiffe://nfltr.xyz/m/m-aaaa")
	// Past 2/3 of its lifetime: the renewal is due at once.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(30 * time.Minute), URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := machinecert.ParseCert(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	cert.MachineID = "m-aaaa"
	if err := (&machinecert.Saved{Cert: *cert, RelayHost: "127.0.0.1", BaseURL: relay.URL}).Store(dir); err != nil {
		t.Fatal(err)
	}
	c := load(dir)
	var logs syncBuf
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c.Run(ctx, slog.New(slog.NewTextHandler(&logs, nil)))
	deadline := time.Now().Add(10 * time.Second) // only against a hang
	for !strings.Contains(logs.String(), "level=WARN") {
		if time.Now().After(deadline) {
			t.Fatalf("no warning for the failed renewal; logs:\n%s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if line := logs.String(); !strings.Contains(line, "could not renew this machine's sign-in yet") || !strings.Contains(line, "expires_in=29m") || !strings.Contains(line, "machine=m-aaaa") {
		t.Fatalf("warning without the machine and the time left: %s", line)
	}
}
