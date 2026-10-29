// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	pb "github.com/nfltr/relay/proto/pb"
)

// What a backend gets from a visitor's request on every HTTP path:
// Origin and Referer as the visitor sent them, the forwarded headers of
// the proxy that ended the visitor's connection, and as Host the public host
// unless the agent rewrites it (Config.RewriteHost, E2EESetup.RewriteHost).

const (
	publicHost = "app.share.example"
	origin     = "https://" + publicHost
	referer    = origin + "/form?x=1"
)

// headerEcho answers with the Host and headers it received, as JSON.
func headerEcho(t *testing.T) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := map[string]string{"Host": r.Host}
		for k := range r.Header {
			h[k] = r.Header.Get(k)
		}
		_ = json.NewEncoder(w).Encode(h)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u
}

func decodeEcho(t *testing.T, resp *http.Response) map[string]string {
	t.Helper()
	defer resp.Body.Close() //nolint:errcheck
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode echo: %v", err)
	}
	return got
}

func wantHeaders(t *testing.T, got map[string]string, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("backend got %s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

// relayHeaders is a request as the relay's edge hands it to the agent: the
// visitor's Origin and Referer, and the relay's own forwarded headers.
func relayHeaders() http.Header {
	return http.Header{
		"Origin":            {origin},
		"Referer":           {referer},
		"X-Forwarded-Host":  {publicHost},
		"X-Forwarded-Proto": {"https"},
		"X-Forwarded-For":   {"203.0.113.7"},
		"X-Real-Ip":         {"203.0.113.7"},
	}
}

func TestTunnelForwardsHeadersAsReverseProxy(t *testing.T) {
	backend := headerEcho(t)
	for _, rewrite := range []bool{false, true} {
		wantHost := publicHost
		if rewrite {
			wantHost = backend.Host
		}
		want := map[string]string{
			"Host": wantHost, "Origin": origin, "Referer": referer,
			"X-Forwarded-Host": publicHost, "X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7",
			"X-Real-Ip": "203.0.113.7",
		}
		name := map[bool]string{false: "preserve", true: "rewrite"}[rewrite]
		t.Run("grpc/"+name, func(t *testing.T) {
			msg := newTestProxyRequest("POST", "form")
			for k, v := range relayHeaders() {
				msg.Request.Headers[k] = &pb.HeaderValueList{HeaderValues: v}
			}
			fwd := resolvedForward{targetBase: backend.String(), strippedPath: "form", rewriteHost: rewrite}
			resp, err := forwardRequest(context.Background(), http.DefaultClient, msg, fwd, "a", nil)
			if err != nil {
				t.Fatal(err)
			}
			wantHeaders(t, decodeEcho(t, resp), want)
		})
		t.Run("link/"+name, func(t *testing.T) {
			h, err := NewTunnelHandler(Config{AgentID: "a", Routes: []Route{{Backend: backend.String()}}, RewriteHost: rewrite})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "http://61.agent-http/form", nil)
			req.Header = relayHeaders()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			wantHeaders(t, decodeEcho(t, rec.Result()), want)
		})
	}
}

// On E2EE sessions the agent is the HTTPS front: X-Forwarded-Host/Proto are
// its own, a client's copies of the forwarded headers never reach the
// backend, and neither do hop-by-hop headers.
func TestE2EEForwardsHeadersAsReverseProxy(t *testing.T) {
	backend := headerEcho(t)
	cert, _, err := generateSelfSignedCert("fwd")
	if err != nil {
		t.Fatal(err)
	}
	cfg := newE2EETLSConfig(cert, "fwd")
	identity := func(h http.Handler) http.Handler { return h }
	clientCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only self-signed cert
	for _, tc := range []struct {
		name    string
		wrap    func(http.Handler) http.Handler
		conn    string // the request's Connection: close takes the pooled last-request path
		rewrite bool
		client  string // the visitor's address the relay named in the open ("" none)
	}{
		{"stream/preserve", nil, "keep-alive", false, ""},
		{"stream/rewrite", nil, "keep-alive", true, ""},
		{"last-request/preserve", nil, "close", false, ""},
		{"last-request/rewrite", nil, "close", true, ""},
		{"http/preserve", identity, "keep-alive", false, ""},
		{"http/rewrite", identity, "keep-alive", true, ""},
		{"stream/client", nil, "keep-alive", false, "203.0.113.7"},
		{"last-request/client", nil, "close", false, "2001:db8::7"},
		{"http/client", identity, "keep-alive", false, "203.0.113.7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := tcpPair(t)
			t.Cleanup(func() { _ = c1.Close() })
			go serveE2EEConn(tls.Server(c2, cfg.tlsConfig), backend, tc.rewrite, clientAddr(tc.client), tc.wrap, slog.New(slog.DiscardHandler))
			cl := tls.Client(c1, clientCfg)
			_ = cl.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.WriteString(cl, "POST /form HTTP/1.1\r\nHost: "+publicHost+"\r\nConnection: "+tc.conn+", X-Hop"+
				"\r\nOrigin: "+origin+"\r\nReferer: "+referer+
				"\r\nX-Forwarded-Host: evil.example\r\nX-Forwarded-For: 198.51.100.1\r\nX-Forwarded-Proto: http\r\nForwarded: for=198.51.100.1\r\nX-Real-Ip: 198.51.100.1"+
				"\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\nProxy-Authorization: Basic eDp5\r\nTe: gzip\r\nX-End: kept"+
				"\r\nAuthorization: Bearer rpc_0123abcd\r\nAuthorization: Bearer app-token"+
				"\r\nContent-Length: 0\r\n\r\n")
			resp, err := http.ReadResponse(bufio.NewReader(cl), nil)
			if err != nil {
				t.Fatal(err)
			}
			got := decodeEcho(t, resp)
			wantHost := publicHost
			if tc.rewrite {
				wantHost = backend.Host
			}
			wantHeaders(t, got, map[string]string{
				"Host": wantHost, "Origin": origin, "Referer": referer,
				"X-Forwarded-Host": publicHost, "X-Forwarded-Proto": "https",
				// The relay's word for the visitor's address, never the visitor's own.
				"X-Forwarded-For": tc.client, "X-Real-Ip": tc.client, "Forwarded": "",
				"X-Hop": "", "Keep-Alive": "", "Proxy-Authorization": "", "Te": "", "X-End": "kept",
				// The app's own token goes on; a relay key never reaches it.
				"Authorization": "Bearer app-token",
			})
		})
	}
}

// An E2EE open's client_addr becomes the session's visitor address only as
// an IP address: anything else (a port, a header injection, a zone) is no
// address, so the backend gets no X-Forwarded-For rather than a made-up
// one. A session that is not E2EE ignores it.
func TestPlanSessionClientAddr(t *testing.T) {
	cert, _, err := generateSelfSignedCert("fwd")
	if err != nil {
		t.Fatal(err)
	}
	e2ee := newE2EETLSConfig(cert, "fwd")
	targets := sessionTargets{defaultBackend: "http://127.0.0.1:1"}
	for _, tc := range []struct{ open, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"2001:db8::7", "2001:db8::7"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"fe80::1%eth0", "fe80::1"},
		{"", ""},
		{"203.0.113.7:443", ""},
		{"203.0.113.7\r\nX-Evil: 1", ""},
		{"example.com", ""},
	} {
		p, err := planSession(&pb.TCPData{E2Ee: true, TargetAddr: "__e2ee__", ClientAddr: tc.open}, targets, e2ee)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if p.client.IsValid() {
			got = p.client.String()
		}
		if got != tc.want {
			t.Errorf("client_addr %q: visitor %q, want %q", tc.open, got, tc.want)
		}
	}
	p, err := planSession(&pb.TCPData{TargetAddr: "127.0.0.1:1", ClientAddr: "203.0.113.7"}, targets, e2ee)
	if err != nil || p.client.IsValid() {
		t.Fatalf("plain session: client %v, err %v; want none", p.client, err)
	}
}
