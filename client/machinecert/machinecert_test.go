// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const day = 24 * time.Hour

// fakeCert is a certificate valid from nb for a day, as the relay issues.
func fakeCert(t *testing.T, nb time.Time) *Cert {
	t.Helper()
	k, _ := NewKey()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: nb, NotAfter: nb.Add(day)}, &x509.Certificate{SerialNumber: big.NewInt(1)}, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCert(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestRenewalLoopJitter: a certificate renews at 2/3 of its lifetime,
// +-10 % of that by its jitter (clamped), always inside the relay's
// renewal window (its last half) and before it expires; the loop waits
// that long with a fresh jitter for each certificate, and retries a failed
// renewal with a doubling backoff until the relay refuses for good.
func TestRenewalLoopJitter(t *testing.T) {
	nb := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		jitter float64
		want   time.Duration
	}{{0, 16 * time.Hour}, {1, 17*time.Hour + 36*time.Minute}, {-1, 14*time.Hour + 24*time.Minute}, {5, 17*time.Hour + 36*time.Minute}, {-5, 14*time.Hour + 24*time.Minute}} {
		at := RenewAt(nb, nb.Add(day), tc.jitter)
		if got := at.Sub(nb); got != tc.want {
			t.Errorf("jitter %v: renews %v after issue, want %v", tc.jitter, got, tc.want)
		}
		if at.Before(nb.Add(day/2)) || !at.Before(nb.Add(day)) {
			t.Errorf("jitter %v: %v is outside the renewal window", tc.jitter, at)
		}
	}

	clock := nb
	var waits []time.Duration
	after := func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		clock = clock.Add(d)
		ch := make(chan time.Time, 1)
		ch <- clock
		return ch
	}
	jitters := []float64{1, -1, 0}
	var renewals, saved int
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err := Loop{
		Now:    func() time.Time { return clock },
		Jitter: func() float64 { j := jitters[0]; jitters = append(jitters[1:], j); return j },
		After:  after,
		Renew: func(_ context.Context, cur *Cert) (*Cert, error) {
			renewals++
			if renewals == 2 || renewals == 3 { // two failures, then on
				return nil, &RefusedError{Status: http.StatusServiceUnavailable}
			}
			if renewals == 6 {
				return nil, &RefusedError{Status: http.StatusUnauthorized, Message: "machine_revoked"}
			}
			return fakeCert(t, clock), nil
		},
		Save: func(*Cert) error { saved++; return nil },
	}.Run(ctx, fakeCert(t, nb))
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.Status != http.StatusUnauthorized {
		t.Fatalf("Run: %v, want the final refusal", err)
	}
	want := []time.Duration{17*time.Hour + 36*time.Minute, 14*time.Hour + 24*time.Minute, RetryMin, 2 * RetryMin, 16 * time.Hour, 17*time.Hour + 36*time.Minute}
	if len(waits) != len(want) {
		t.Fatalf("waits %v, want %v", waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("wait %d: %v, want %v (all %v)", i, waits[i], want[i], waits)
		}
	}
	if saved != 3 {
		t.Fatalf("saved %d certificates, want 3", saved)
	}

	// Cancelled while waiting: Run ends with nil.
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	if err := (Loop{Renew: func(context.Context, *Cert) (*Cert, error) { t.Fatal("renewed"); return nil, nil }}).Run(ctx, fakeCert(t, time.Now())); err != nil {
		t.Fatalf("cancelled: %v", err)
	}
}

// TestClientNeverSendsTheKey: the machine sends its CSR (signed by its
// key), the certificate it holds and, to rotate, the current key's proof
// over the new CSR; never a private key. The relay's answer is the chain.
func TestClientNeverSendsTheKey(t *testing.T) {
	caKey, _ := NewKey()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(day), KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code, Chain string
			CSR, Proof  []byte
		}
		raw, _ := json.Marshal(r.URL.Path)
		var b strings.Builder
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		js, _ := json.Marshal(req)
		b.Write(raw)
		b.Write(js)
		bodies = append(bodies, b.String())
		csr, err := x509.ParseCertificateRequest(req.CSR)
		if err != nil || csr.CheckSignature() != nil {
			http.Error(w, "bad_csr", http.StatusBadRequest)
			return
		}
		if r.URL.Path == ReissuePath {
			cur, err := ParseCert([]byte(req.Chain))
			if err != nil {
				http.Error(w, "not_machine_certificate", http.StatusUnauthorized)
				return
			}
			if req.Proof != nil {
				h := sha256.Sum256(req.CSR)
				if !ecdsa.VerifyASN1(cur.Leaf.PublicKey.(*ecdsa.PublicKey), h[:], req.Proof) {
					http.Error(w, "bad_rotation_proof", http.StatusBadRequest)
					return
				}
			}
		} else if req.Code != "c1" {
			http.Error(w, "enrol_refused", http.StatusForbidden)
			return
		}
		u, _ := url.Parse("spiffe://nfltr.xyz/m/m1")
		der, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), URIs: []*url.URL{u}, NotBefore: time.Now(), NotAfter: time.Now().Add(day)}, caCert, csr.PublicKey, caKey)
		chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		_ = json.NewEncoder(w).Encode(map[string]any{"machine_id": "m1", "name": "pi", "chain": string(chain) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	key, _ := NewKey()
	if _, err := c.Enrol(t.Context(), "wrong", "", "", key); err == nil || !err.(*RefusedError).Final() {
		t.Fatalf("a wrong code: %v, want a final refusal", err)
	}
	cert, err := c.Enrol(t.Context(), "c1", "", "", key)
	if err != nil || cert.MachineID != "m1" || !cert.Leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatalf("enrol: %+v, %v", cert, err)
	}
	if _, err := c.Renew(t.Context(), cert, key); err != nil {
		t.Fatalf("renew: %v", err)
	}
	next, _ := NewKey()
	rotated, err := c.Rotate(t.Context(), cert, key, next)
	if err != nil || !rotated.Leaf.PublicKey.(*ecdsa.PublicKey).Equal(&next.PublicKey) {
		t.Fatalf("rotate: %v", err)
	}
	if tc := rotated.TLS(next); tc.Leaf != rotated.Leaf || tc.PrivateKey != next {
		t.Fatal("TLS certificate")
	}
	for _, b := range bodies {
		if strings.Contains(b, "PRIVATE KEY") {
			t.Fatalf("a request carried a private key: %s", b)
		}
	}
	if len(bodies) != 4 {
		t.Fatalf("%d requests, want 4", len(bodies))
	}
}

// TestKeyFileOwnerOnly: SaveKey writes 0600 and LoadKey reads it back;
// a key file group or others may read is refused.
func TestKeyFileOwnerOnly(t *testing.T) {
	key, _ := NewKey()
	path := filepath.Join(t.TempDir(), "machine.key")
	if err := SaveKey(path, key); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %o, want 600", st.Mode().Perm())
	}
	got, err := LoadKey(path)
	if err != nil || !got.Equal(key) {
		t.Fatalf("LoadKey: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("a world-readable key file loaded")
	}
}
