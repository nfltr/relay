// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relayoutage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestThrottledResendsAfterRetryAfter (G-C1): a relay that throttles a
// request (429, e.g. share issuance under the pre-auth limit) answered before
// handling it, so the request is resent, body and all, after its Retry-After.
// `nfltr http` used to print no share URL: 150 tunnels started at once lost
// theirs.
func TestThrottledResendsAfterRetryAfter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if calls.Add(1) < 3 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	client := &http.Client{Transport: Throttled(nil)}
	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"ttl":"1h"}`))
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != `{"ttl":"1h"}` || calls.Load() != 3 {
		t.Fatalf("got %d %q after %d calls; want 200 echoing the body after 3", resp.StatusCode, body, calls.Load())
	}
	if waited := time.Since(start); waited < 2*time.Second {
		t.Fatalf("resent after %s; want each Retry-After (1 s) honoured", waited)
	}
}

// TestThrottledReturnsTheRefusalItCannotWaitOut: a Retry-After past the
// request's deadline is returned at once, so the caller reports it.
func TestThrottledReturnsTheRefusalItCannotWaitOut(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, nil)
	start := time.Now()
	resp, err := (&http.Client{Transport: Throttled(nil)}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || calls.Load() != 1 || time.Since(start) > time.Second {
		t.Fatalf("got %d after %d calls in %s; want the 429 at once", resp.StatusCode, calls.Load(), time.Since(start))
	}
}
