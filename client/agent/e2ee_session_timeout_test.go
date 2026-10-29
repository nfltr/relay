// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

// An E2EE session is a public share's TLS conn ending at the agent, before
// any backend is involved: a client that stalls its handshake or its first
// request's headers must not hold the session (and its relay stream) forever
// (gosec G112). A session
// that has sent a request keeps living past that bound while idle.
func TestE2EESessionBoundsHandshakeAndHeaders(t *testing.T) {
	old := e2eeHeaderTimeout
	e2eeHeaderTimeout = 200 * time.Millisecond
	t.Cleanup(func() { e2eeHeaderTimeout = old })

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(backend.Close)
	u, _ := url.Parse(backend.URL)
	cert, _, err := generateSelfSignedCert("timeout")
	if err != nil {
		t.Fatal(err)
	}
	cfg := newE2EETLSConfig(cert, "timeout")
	tun := &tcpTunnel{logger: slog.New(slog.DiscardHandler)}
	clientCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only self-signed cert
	identity := func(h http.Handler) http.Handler { return h }

	for _, tc := range []struct {
		name string
		wrap func(http.Handler) http.Handler  // nil: stream path
		run  func(t *testing.T, cl *tls.Conn) // the client's part
		ends bool                             // the agent ends the session on its own
	}{
		{"stream/no-handshake", nil, func(*testing.T, *tls.Conn) {}, true},
		{"stream/partial-headers", nil, partialHeaders, true},
		{"http/no-handshake", identity, func(*testing.T, *tls.Conn) {}, true},
		{"http/partial-headers", identity, partialHeaders, true},
		{"stream/idle-after-request", nil, requestsAcrossIdle, false},
		{"http/idle-after-request", identity, requestsAcrossIdle, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := tcpPair(t)
			t.Cleanup(func() { _ = c1.Close() })
			done := make(chan struct{})
			go func() {
				defer close(done)
				serveE2EEConn(tls.Server(c2, cfg.tlsConfig), u, false, netip.Addr{}, tc.wrap, tun.logger)
			}()
			tc.run(t, tls.Client(c1, clientCfg))
			if !tc.ends {
				_ = c1.Close()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("session still open 5s after a 200ms header bound")
			}
		})
	}
}

func partialHeaders(t *testing.T, cl *tls.Conn) {
	if _, err := io.WriteString(cl, "GET / HTTP/1.1\r\nHost: x\r\n"); err != nil {
		t.Fatal(err)
	}
}

// requestsAcrossIdle sends a request, idles past the header bound, then
// sends another on the same session: both must be answered.
func requestsAcrossIdle(t *testing.T, cl *tls.Conn) {
	_ = cl.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(cl)
	for i := range 2 {
		if i == 1 {
			time.Sleep(3 * e2eeHeaderTimeout)
		}
		if _, err := io.WriteString(cl, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
