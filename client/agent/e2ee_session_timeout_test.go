// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"crypto/tls"
	"fmt"
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
// (gosec G112). A session that has sent a request keeps living past that bound while idle.
func TestE2EESessionBoundsHandshakeAndHeaders(t *testing.T) {
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

	old := e2eeHeaderTimeout
	t.Cleanup(func() { e2eeHeaderTimeout = old })

	for _, tc := range []struct {
		name string
		wrap func(http.Handler) http.Handler // nil: stream path
		// run is the client's part. A failure is load's, not the agent's,
		// when the step that failed was not done within the bound (slow).
		run  func(cl *tls.Conn, start time.Time) (slow bool, err error)
		ends bool // the agent ends the session on its own
	}{
		{"stream/no-handshake", nil, noHandshake, true},
		{"stream/partial-headers", nil, partialHeaders, true},
		{"http/no-handshake", identity, noHandshake, true},
		{"http/partial-headers", identity, partialHeaders, true},
		{"stream/idle-after-request", nil, requestsAcrossIdle, false},
		{"http/idle-after-request", identity, requestsAcrossIdle, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The bound is short for the test's speed; a run whose client
			// was too slow for it (a loaded machine) proves nothing and runs
			// again with twice the bound.
			for bound := 200 * time.Millisecond; ; bound *= 2 {
				e2eeHeaderTimeout = bound
				c1, c2 := tcpPair(t)
				start := time.Now()
				done := make(chan struct{})
				go func() {
					defer close(done)
					serveE2EEConn(tls.Server(c2, cfg.tlsConfig), u, false, netip.Addr{}, tc.wrap, tun.logger)
				}()
				slow, err := tc.run(tls.Client(c1, clientCfg), start)
				if err != nil || !tc.ends {
					_ = c1.Close()
				}
				select {
				case <-done:
				case <-time.After(bound + 5*time.Second):
					t.Fatalf("session still open 5s after its %s header bound", bound)
				}
				_ = c1.Close()
				if err == nil {
					return
				}
				if !slow || bound >= 5*time.Second {
					t.Fatalf("header bound %s: %v", bound, err)
				}
				t.Logf("header bound %s: %v, after the bound: again", bound, err)
			}
		})
	}
}

func noHandshake(*tls.Conn, time.Time) (bool, error) { return false, nil }

// partialHeaders completes the handshake and stalls in the headers.
func partialHeaders(cl *tls.Conn, start time.Time) (bool, error) {
	_, err := io.WriteString(cl, "GET / HTTP/1.1\r\nHost: x\r\n")
	return time.Since(start) >= e2eeHeaderTimeout, err
}

// requestsAcrossIdle sends a request, idles past the header bound, then
// sends another on the same session: both must be answered.
func requestsAcrossIdle(cl *tls.Conn, start time.Time) (bool, error) {
	_ = cl.SetDeadline(time.Now().Add(2*e2eeHeaderTimeout + 10*time.Second))
	br := bufio.NewReader(cl)
	for i := range 2 {
		if i == 1 {
			time.Sleep(2 * e2eeHeaderTimeout)
			start = time.Now()
		}
		if _, err := io.WriteString(cl, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			return time.Since(start) >= e2eeHeaderTimeout, fmt.Errorf("request %d: %w", i, err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return time.Since(start) >= e2eeHeaderTimeout, fmt.Errorf("response %d: %w", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return false, nil
}
