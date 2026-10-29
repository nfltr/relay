// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// streamSession runs serveE2EEStream for one client TCP conn (standing in
// for the decrypted E2EE session) against backend and returns the client end.
func streamSession(t *testing.T, backend string) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serveE2EEStream(c, backend, "backend.local", netip.Addr{}, slog.New(slog.DiscardHandler))
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.TCPConn)
}

func echoBackend(t *testing.T, conns *atomic.Int32) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Host", r.Host)
		w.Header().Set("X-Proto", r.Proto)
		w.Header().Set("X-Hop", r.Header.Get("Keep-Alive"))
		w.Header().Set("X-Trailer", r.Trailer.Get("X-Sum"))
		_, _ = w.Write(body)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew && conns != nil {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// TestE2EEStreamForwardsRequestsAsSent: keep-alive requests on one session
// share one backend connection; Host becomes the backend's (a rewriting
// agent), hop-by-hop headers other than Connection and Upgrade go, and
// everything else (protocol version, Content-Length and chunked bodies with
// trailers) goes on as the client sent it.
func TestE2EEStreamForwardsRequestsAsSent(t *testing.T) {
	var conns atomic.Int32
	c := streamSession(t, echoBackend(t, &conns))
	br := bufio.NewReader(c)
	reqs := []string{
		"GET /a HTTP/1.1\r\nHost: public.example\r\nKeep-Alive: timeout=5\r\n\r\n",
		"POST /b HTTP/1.1\r\nHost: public.example\r\nContent-Length: 5\r\n\r\nhello",
		"POST /c HTTP/1.1\r\nHost: public.example\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nX-Sum: 5\r\n\r\n",
	}
	for i, raw := range reqs {
		if _, err := io.WriteString(c, raw); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		if got := resp.Header.Get("X-Host"); got != "backend.local" {
			t.Errorf("request %d: backend saw Host %q, want backend.local", i, got)
		}
		switch i {
		case 0:
			if resp.Header.Get("X-Hop") != "" { // dropped as a reverse proxy drops it
				t.Errorf("hop-by-hop header forwarded: %q", resp.Header.Get("X-Hop"))
			}
		case 1:
			if string(body) != "hello" {
				t.Errorf("body %q", body)
			}
		case 2:
			if string(body) != "abcde" || resp.Header.Get("X-Trailer") != "5" {
				t.Errorf("chunked body %q trailer %q", body, resp.Header.Get("X-Trailer"))
			}
		}
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d backend connections for one keep-alive session, want 1", n)
	}
}

// TestE2EEStreamHTTP10: an HTTP/1.0 request stays HTTP/1.0, so the backend
// does not answer it with chunked encoding the client cannot read.
func TestE2EEStreamHTTP10(t *testing.T) {
	c := streamSession(t, echoBackend(t, nil))
	_, _ = io.WriteString(c, "GET / HTTP/1.0\r\nHost: public.example\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.Header.Get("X-Proto"); got != "HTTP/1.0" {
		t.Fatalf("backend saw %s, want HTTP/1.0", got)
	}
}

// TestE2EEStreamHalfClose: a client that half-closes after its request
// still gets the response, then the session ends.
func TestE2EEStreamHalfClose(t *testing.T) {
	c := streamSession(t, echoBackend(t, nil))
	_, _ = io.WriteString(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(c) // returns at EOF: the session ended
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(all), "HTTP/1.1 200") || !strings.HasSuffix(string(all), "\r\n\r\nhi") {
		t.Fatalf("response after half-close: %q", all)
	}
}

// TestE2EEStreamExpectContinue: the head reaches the backend before the
// body is read, so a client waiting for 100 Continue gets it.
func TestE2EEStreamExpectContinue(t *testing.T) {
	c := streamSession(t, echoBackend(t, nil))
	br := bufio.NewReader(c)
	_, _ = io.WriteString(c, "PUT / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n")
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 100") {
		t.Fatalf("want 100 Continue first, got %q, %v", line, err)
	}
	_, _ = br.ReadString('\n') // blank line after the 100
	_, _ = io.WriteString(c, "data")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := io.ReadAll(resp.Body); string(body) != "data" {
		t.Fatalf("body %q", body)
	}
}

// TestE2EEStreamUpgrade: after an upgrade the session is a byte copy both ways.
func TestE2EEStreamUpgrade(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw) // echo
	}))
	defer srv.Close()
	c := streamSession(t, srv.Listener.Addr().String())
	br := bufio.NewReader(c)
	_, _ = io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	_, _ = io.WriteString(c, "GET / HTTP/1.1 is just bytes now\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "GET / HTTP/1.1 is just bytes now\n" {
		t.Fatalf("echo %q, %v", line, err)
	}
}

// TestE2EEStreamBackendDown: a backend that cannot be reached gets the
// client a 502, on a dedicated connection and through the pool alike.
func TestE2EEStreamBackendDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	for _, conn := range []string{"keep-alive", "close"} {
		c := streamSession(t, addr)
		_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: "+conn+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("Connection: %s: want 502, got %v, %v", conn, resp, err)
		}
	}
}

// TestE2EEStreamLastRequestUsesThePool: sessions of one request each
// (Connection: close, as clients without keep-alive send) share the pooled
// backend connections instead of dialing one per session, and the client
// still gets Connection: close.
func TestE2EEStreamLastRequestUsesThePool(t *testing.T) {
	var conns atomic.Int32
	backend := echoBackend(t, &conns)
	for i := range 5 {
		c := streamSession(t, backend)
		_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
		all, err := io.ReadAll(c) // the session ends after the response
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(all))), nil)
		if err != nil {
			t.Fatalf("session %d: %v in %q", i, err, all)
		}
		if !resp.Close || resp.Header.Get("X-Host") != "backend.local" {
			t.Fatalf("session %d: close %v, backend Host %q", i, resp.Close, resp.Header.Get("X-Host"))
		}
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d backend connections for 5 one-request sessions, want 1 (pooled)", n)
	}
}

// BenchmarkE2EESessionPaths: one E2EE session's agent-side work after the
// relay (TLS server over a pipe, then the backend), stream path vs HTTP path,
// a connection per request (Connection: close) or 10 requests per
// connection. Run with -cpu 1: client and backend do the same work on both
// paths, so the difference in ns/op is the agent's.
func BenchmarkE2EESessionPaths(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 1024))
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	cert, _, err := generateSelfSignedCert("bench")
	if err != nil {
		b.Fatal(err)
	}
	cfg := newE2EETLSConfig(cert, "bench")
	tun := &tcpTunnel{logger: slog.New(slog.DiscardHandler)}
	clientCfg := &tls.Config{InsecureSkipVerify: true, ClientSessionCache: tls.NewLRUClientSessionCache(8)} //nolint:gosec // bench-only self-signed cert
	for _, path := range []string{"stream", "http"} {
		for _, perConn := range []int{1, 10} {
			b.Run(fmt.Sprintf("%s/requests-per-conn=%d", path, perConn), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					c1, c2 := tcpPair(b)
					srv := tls.Server(c2, cfg.tlsConfig)
					go func() {
						if path == "http" {
							serveE2EEHTTP(srv, u, u.Host, netip.Addr{}, nil, tun.logger)
							return
						}
						_ = srv.Handshake()
						serveE2EEStream(srv, u.Host, u.Host, netip.Addr{}, tun.logger)
					}()
					cl := tls.Client(c1, clientCfg)
					br := bufio.NewReader(cl)
					for i := range perConn {
						conn := "keep-alive"
						if i == perConn-1 {
							conn = "close"
						}
						_, _ = io.WriteString(cl, "GET / HTTP/1.1\r\nHost: x\r\nConnection: "+conn+"\r\n\r\n")
						resp, err := http.ReadResponse(br, nil)
						if err != nil {
							b.Fatal(err)
						}
						_, _ = io.Copy(io.Discard, resp.Body)
					}
					_ = cl.Close()
				}
			})
		}
	}
}

// tcpPair is two ends of a loopback TCP connection (net.Pipe is unbuffered:
// a TLS close_notify from each end at once would wait on the other).
func tcpPair(tb testing.TB) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	c2, err := ln.Accept()
	if err != nil {
		tb.Fatal(err)
	}
	return c1, c2
}
