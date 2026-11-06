// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/client/relaytrust/relaytrusttest"
)

// connectProxy is an HTTP proxy that only tunnels CONNECT (a site's only
// way out), recording each target and Proxy-Authorization; status other
// than 0 refuses every CONNECT with it.
type connectProxy struct {
	*httptest.Server
	mu      sync.Mutex
	targets []string
	auth    []string
}

func newConnectProxy(t *testing.T, status int) *connectProxy {
	p := &connectProxy{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		p.mu.Lock()
		p.targets, p.auth = append(p.targets, r.Host), append(p.auth, r.Header.Get("Proxy-Authorization"))
		p.mu.Unlock()
		if status != 0 {
			http.Error(w, "refused", status)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
		_, _ = io.Copy(c, up)
		_ = c.Close()
	}))
	t.Cleanup(p.Close)
	return p
}

// TestDialConnThroughConnectProxy: a data connection or agent link
// reaches the relay through the HTTPS proxy the environment names, by
// CONNECT, with Basic credentials from the proxy URL; TLS to the relay is
// end to end through it. A proxy that refuses the CONNECT is an error
// naming the proxy (credentials redacted), not a direct dial.
func TestDialConnThroughConnectProxy(t *testing.T) {
	set := relaytrusttest.New(t)
	srv := relaytrusttest.Serve(t, set.Kinds[0].Cert)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	cfg := &tls.Config{RootCAs: set.CA}
	addr := net.JoinHostPort(relaytrusttest.Host, p)

	proxy := newConnectProxy(t, 0)
	u, _ := url.Parse(proxy.URL)
	u.User = url.UserPassword("site", "s3cret")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialConn(ctx, u, true, cfg, relaytrusttest.Host, port)
	if err != nil {
		t.Fatalf("through the proxy: %v", err)
	}
	// The relay answers HTTP on its TLS port: a request proves the bytes
	// after the handshake are the relay's.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(conn)
	_ = conn.Close()
	if !strings.HasPrefix(string(got), "HTTP/1.1 ") {
		t.Fatalf("no answer from the relay through the proxy: %q", got)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("site:s3cret"))
	proxy.mu.Lock()
	if len(proxy.targets) != 1 || proxy.targets[0] != addr || proxy.auth[0] != want {
		t.Errorf("proxy saw CONNECT %v auth %v, want one to %s with Basic credentials", proxy.targets, proxy.auth, addr)
	}
	proxy.mu.Unlock()

	refusing := newConnectProxy(t, http.StatusProxyAuthRequired)
	r, _ := url.Parse(refusing.URL)
	r.User = url.UserPassword("site", "s3cret")
	_, err = dialConn(ctx, r, true, cfg, relaytrusttest.Host, port)
	if err == nil || !strings.Contains(err.Error(), "407") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("a refusing proxy: %v, want an error naming 407 without the password", err)
	}
	if _, err := dialConn(ctx, &url.URL{Scheme: "socks5", Host: "127.0.0.1:1"}, true, cfg, relaytrusttest.Host, port); err == nil {
		t.Fatal("a socks5 proxy was accepted; only http:// carries CONNECT here")
	}
}
