// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relayoutage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// A relay restart (deploy window) refuses connections for seconds. A request
// that never reached the relay is safe to resend whatever its method, so the
// relay client rides the outage out instead of failing the dispatch, record or
// status call.
func TestTransportRidesOutRefusedConnections(t *testing.T) {
	addr := freeAddr(t)
	got := make(chan string, 1)
	go func() {
		time.Sleep(400 * time.Millisecond)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			got <- "listen: " + err.Error()
			return
		}
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			got <- string(b)
		}))
		srv.Listener = l
		srv.Start()
		t.Cleanup(srv.Close)
	}()

	client := &http.Client{Transport: Transport(http.DefaultTransport)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/api/v1/orchestration/dispatch", bytes.NewReader([]byte(`{"task_id":"t1"}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed instead of riding out the outage: %v", err)
	}
	_ = resp.Body.Close()
	if body := <-got; body != `{"task_id":"t1"}` {
		t.Fatalf("relay received %q, want the full original body", body)
	}
}

// The ride-out is bounded by the caller's context: a relay that never comes
// back still fails with the dial error once the deadline passes.
func TestTransportHonoursCallerDeadline(t *testing.T) {
	client := &http.Client{Transport: Transport(http.DefaultTransport)}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+freeAddr(t)+"/api/v1/orchestration/tasks/t1", nil)
	start := time.Now()
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("request to an absent relay succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error = %v, want the deadline or the dial error", err)
	}
	if elapsed := time.Since(start); elapsed < 400*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("returned after %v, want about the caller deadline", elapsed)
	}
}
