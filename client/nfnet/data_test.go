// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/client/relaytrust"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// connectProxy is an HTTP CONNECT proxy on loopback: it answers status to
// every CONNECT and, on 200, splices the client to the requested address.
// Each request arrives on reqs.
func connectProxy(t *testing.T, status int) (*url.URL, <-chan *http.Request) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	reqs := make(chan *http.Request, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				reqs <- req
				if status != http.StatusOK {
					_, _ = io.WriteString(c, "HTTP/1.1 "+strconv.Itoa(status)+" "+http.StatusText(status)+"\r\n\r\n")
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer up.Close() //nolint:errcheck
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return &url.URL{Scheme: "http", User: url.UserPassword("site", "s3cret"), Host: ln.Addr().String()}, reqs
}

// echoServer stands in for the relay: it echoes what it reads.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }() //nolint:errcheck
		}
	}()
	return ln.Addr().String()
}

func echoOnce(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through the connection: %q, %v", buf, err)
	}
}

// A data connection from a network whose only way out is an HTTP proxy is
// a CONNECT to the relay's address, with the proxy's credentials from its
// URL; a refused CONNECT fails with the proxy's answer; without a proxy
// the relay is dialled directly.
func TestDialThrough(t *testing.T) {
	relay := echoServer(t)
	proxy, reqs := connectProxy(t, http.StatusOK)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialThrough(ctx, proxy, relay)
	if err != nil {
		t.Fatalf("dial through the proxy: %v", err)
	}
	echoOnce(t, c)
	_ = c.Close()
	req := <-reqs
	if req.Method != http.MethodConnect || req.Host != relay {
		t.Fatalf("the proxy got %s %s, want CONNECT %s", req.Method, req.Host, relay)
	}
	if got, want := req.Header.Get("Proxy-Authorization"), "Basic "+base64.StdEncoding.EncodeToString([]byte("site:s3cret")); got != want {
		t.Fatalf("Proxy-Authorization %q, want %q", got, want)
	}

	refusing, _ := connectProxy(t, http.StatusProxyAuthRequired)
	if _, err := dialThrough(ctx, refusing, "relay.example:443"); err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("err %v, want the proxy's 407", err)
	}

	if c, err = dialThrough(ctx, nil, relay); err != nil {
		t.Fatal(err)
	}
	echoOnce(t, c)
	_ = c.Close()
}

func TestOpenStatusError(t *testing.T) {
	for status, code := range map[int]Code{401: CodeAuth, 403: CodeAuth, 402: CodeBalanceExhausted, 404: CodeNotFound, 503: CodeRefused, 400: CodeUsage, 426: CodeUsage, 502: CodeUnreachable} {
		if e := openStatusError(status, "why"); e.Code != code || !strings.Contains(e.Message, strconv.Itoa(status)) || !strings.Contains(e.Message, "why") {
			t.Errorf("%d: %+v, want code %s", status, e, code)
		}
	}
}

// A session cut after it opened is a reset, except where the cut says
// why: a leaving relay's drain deadline (reset, ReasonDrainDeadline), the
// credential revoked or expired (auth: a caller does not retry a key the
// relay no longer takes), the balance exhausted.
func TestResetErrorTypesTheCut(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   Code
		reason string
	}{
		{errors.New("connection closed"), CodeReset, ""},
		{&link.Abort{Code: link.CodeDrainDeadline}, CodeReset, ReasonDrainDeadline},
		{&link.Abort{Code: link.CodeConnLost}, CodeReset, ""},
		{&link.Abort{Code: dataplane.AbortCode(relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED), Msg: "credential revoked"}, CodeAuth, "ERROR_REASON_UNAUTHENTICATED"},
		{&link.Abort{Code: dataplane.AbortCode(relayv1.ErrorReason_ERROR_REASON_BALANCE_EXHAUSTED), Msg: "balance exhausted"}, CodeBalanceExhausted, "ERROR_REASON_BALANCE_EXHAUSTED"},
		{&link.Abort{Code: dataplane.AbortCode(relayv1.ErrorReason_ERROR_REASON_TARGET_UNREACHABLE)}, CodeReset, ""},
	} {
		if e := resetError(tc.err); e.Code != tc.code || e.Reason != tc.reason {
			t.Errorf("%v: %+v, want code %s reason %q", tc.err, e, tc.code, tc.reason)
		}
	}
}

// Config.ClientCert is presented to the relay (no key); a relay that
// refuses it (401) is CodeAuth.
func TestClientCertReachesTheRelay(t *testing.T) {
	r := newDataRelay(t, true)
	cfg := r.config(true)
	cfg.APIKey, cfg.ClientCert = "", r.org.cli.Certificate
	c, err := dial(t, dialer(t, cfg), web("echo"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	echoAndHalfClose(t, c, "with a certificate")
	_ = c.Close()

	refusing := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 || req.Header.Get("X-API-Key") != "" {
			t.Errorf("the relay got no certificate, or a key")
		}
		http.Error(w, "machine revoked", http.StatusUnauthorized)
	}))
	refusing.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	refusing.StartTLS()
	t.Cleanup(refusing.Close)
	cfg = Config{Relay: refusing.Listener.Addr().String(), ClientCert: r.org.cli.Certificate,
		RelayTLS: relaytrust.WithPin(&tls.Config{ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}, relaytrust.Fingerprint(refusing.Certificate().Raw))}
	_, err = dialer(t, cfg).E2EEPolicy(t.Context())
	wantCode(t, "refused certificate", err, CodeAuth, "")
}
