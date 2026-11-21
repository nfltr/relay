// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/client/machinecert"
)

// Handshakes that find the certificate expired at once renew it once: the
// others take that renewal (lane CERTGAPS, from CERTPROOF: a second renewal
// got 409 renew_too_early and logged that the relay does not answer).
func TestExpiredCertificateRenewsOnceForConcurrentHandshakes(t *testing.T) {
	var key *ecdsa.PrivateKey
	var renewals atomic.Int32
	c, k := expiredCredential(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != machinecert.ReissuePath {
			http.NotFound(w, r)
			return
		}
		if renewals.Add(1) > 1 {
			http.Error(w, "renew_too_early: the certificate is not in its renewal window", http.StatusConflict)
			return
		}
		now := time.Now()
		_ = json.NewEncoder(w).Encode(map[string]any{"machine_id": "m-aaaa", "chain": certPEM(t, key, now, now.Add(24*time.Hour)), "not_after": now.Add(24 * time.Hour)})
	})
	key = k
	get := c.TLSConfig(nil).GetClientCertificate
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got, err := get(&tls.CertificateRequestInfo{}); err != nil || !time.Now().Before(got.Leaf.NotAfter) {
				t.Errorf("handshake certificate: %v", err)
			}
		})
	}
	wg.Wait()
	if n := renewals.Load(); n != 1 {
		t.Fatalf("%d renewals for one expiry, want 1", n)
	}
}
