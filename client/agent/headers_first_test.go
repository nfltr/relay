// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
)

// Headers before body: a backend that sends its response headers and only
// later its body (SSE, long poll, any chunked stream) must have its
// headers reach the visitor at once, on every way the agent serves HTTP.
// Each backend holds its body until the visitor has the headers; a path
// that waits for the body fails the 5 s bound.

// heldBodyContentTypes are streamed responses the backend answers with.
var heldBodyContentTypes = []string{"text/event-stream", "text/plain", "application/json", "text/html"}

// heldBodyBackend sends 200 with ct and its headers, then "body" once
// release is closed (or after 8 s).
func heldBodyBackend(t *testing.T, ct string, release <-chan struct{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.Header().Set("X-Held", "1")
		w.WriteHeader(http.StatusOK)
		http.NewResponseController(w).Flush() //nolint:errcheck
		select {
		case <-release:
		case <-time.After(8 * time.Second): // past within's bound: a failed test still ends
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "body")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// within fails the test unless f returns within 5 s.
func within[T any](t *testing.T, what string, f func() T) T {
	t.Helper()
	got := make(chan T, 1)
	go func() { got <- f() }()
	select {
	case v := <-got:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: no headers while the backend held its body", what)
		var zero T
		return zero
	}
}

func TestHeadersReachTheVisitorBeforeTheBody(t *testing.T) {
	for _, ct := range heldBodyContentTypes {
		t.Run("tunnel/"+ct, func(t *testing.T) { // link sessions and nfltr up http services
			release := make(chan struct{})
			backend := heldBodyBackend(t, ct, release)
			h, err := NewTunnelHandler(Config{AgentID: "a", Routes: []Route{{Backend: backend.URL}}, Logger: slog.New(slog.DiscardHandler)})
			if err != nil {
				t.Fatal(err)
			}
			front := httptest.NewServer(h)
			t.Cleanup(front.Close)
			resp := within(t, ct, func() *http.Response {
				resp, err := http.Get(front.URL + "/")
				if err != nil {
					t.Error(err)
				}
				return resp
			})
			if resp == nil {
				return
			}
			defer resp.Body.Close() //nolint:errcheck
			close(release)
			if b, _ := io.ReadAll(resp.Body); resp.Header.Get("X-Held") != "1" || string(b) != "body" {
				t.Fatalf("headers %v body %q", resp.Header, b)
			}
		})
		for _, last := range []bool{false, true} { // keep-alive: a byte copy; Connection: close: the pooled transport
			name := "e2ee/keep-alive/" + ct
			if last {
				name = "e2ee/connection-close/" + ct
			}
			t.Run(name, func(t *testing.T) {
				release := make(chan struct{})
				backend := heldBodyBackend(t, ct, release)
				client, server := net.Pipe()
				t.Cleanup(func() { _ = client.Close() })
				go serveE2EEStream(server, strings.TrimPrefix(backend.URL, "http://"), "", netip.Addr{}, slog.New(slog.DiscardHandler))
				req, _ := http.NewRequest("GET", "http://backend/", nil)
				req.Close = last
				go func() { _ = req.Write(client) }()
				br := bufio.NewReader(client)
				resp := within(t, name, func() *http.Response {
					resp, err := http.ReadResponse(br, req)
					if err != nil {
						t.Error(err)
					}
					return resp
				})
				if resp == nil {
					return
				}
				close(release)
				if b, _ := io.ReadAll(resp.Body); resp.Header.Get("X-Held") != "1" || string(b) != "body" {
					t.Fatalf("headers %v body %q", resp.Header, b)
				}
			})
		}
		t.Run("connect-http/"+ct, func(t *testing.T) { // ConnectHTTP messages
			release := make(chan struct{})
			backend := heldBodyBackend(t, ct, release)
			msg := newTestProxyRequest("GET", "")
			fwd := resolvedForward{targetBase: backend.URL}
			resp, err := forwardRequest(context.Background(), &http.Client{}, msg, fwd, "a", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close() //nolint:errcheck
			sent := make(chan *pb.HTTPProxyResponse, 16)
			go func() {
				_, _ = sendResponse(context.Background(), func(m *pb.HTTPProxyResponse) error { sent <- m; return nil }, resp, msg, fwd, nil)
			}()
			first := within(t, ct, func() *pb.HTTPProxyResponse { return <-sent })
			close(release)
			if first == nil || first.Response.StatusCode != http.StatusOK || first.Response.Headers["X-Held"] == nil {
				t.Fatalf("first message %v", first)
			}
		})
	}
}
