// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/nfltr/relay/client/relaytrust"
	"github.com/nfltr/relay/proto/wire/tlsbatch"
)

// DialConn opens a connection to the relay at host:port with the TLS of
// NewMTLSClientConn (tlsCfg set) or NewClientConn (secure), handshake done
// and writes batched (tlsbatch); plaintext when neither. It is a TCP
// tunnel's data connection and the agent link (pkg/agent RelayDialer).
// When the environment names an HTTPS proxy for the relay (HTTPS_PROXY,
// NO_PROXY: net/http's rules, as gRPC's own dial follows), it goes
// through that proxy's CONNECT, as gRPC does; TLS to the relay is end to
// end through it.
func DialConn(ctx context.Context, secure bool, tlsCfg *tls.Config, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	proxy, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
	if err != nil {
		return nil, err
	}
	return dialConn(ctx, proxy, secure, tlsCfg, host, port)
}

// dialConn is DialConn through proxy (nil: direct).
func dialConn(ctx context.Context, proxy *url.URL, secure bool, tlsCfg *tls.Config, host string, port int) (net.Conn, error) {
	nc, err := DialThrough(ctx, proxy, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	pinned := tlsCfg == nil // the relay pin applies, so its hint does
	if tlsCfg = RelayTLS(secure, tlsCfg, host); tlsCfg == nil {
		return nc, nil
	}
	tc := tlsbatch.Client(nc, tlsCfg)
	if err := tc.Conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
		_ = nc.Close()
		if !pinned {
			return nil, err
		}
		return nil, relaytrust.Explain(err)
	}
	return tc, nil
}

// RelayTLS is the TLS configuration DialConn uses toward the relay at host:
// a clone of tlsCfg (NewMTLSClientConn's), else the relay's with its pin
// (secure), else nil (plaintext). Its ServerName is host unless set.
func RelayTLS(secure bool, tlsCfg *tls.Config, host string) *tls.Config {
	switch {
	case tlsCfg != nil:
		tlsCfg = tlsCfg.Clone()
	case secure:
		tlsCfg = relayTLSConfig(&options{})
	default:
		return nil
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = host
	}
	return tlsCfg
}

// DialThrough connects to addr directly (proxy nil) or through an http://
// proxy's CONNECT, with Basic credentials from the proxy URL's user info.
// It returns once the proxy answered 200: the bytes after it are addr's.
// Neither golang.org/x/net/proxy (SOCKS5 only) nor the standard library
// exports an HTTP CONNECT dialer; gRPC's is internal.
func DialThrough(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	d := &net.Dialer{}
	if proxy == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	if proxy.Scheme != "http" {
		return nil, fmt.Errorf("proxy %s: only an http:// proxy can carry the relay's connections", proxy.Redacted())
	}
	host := proxy.Host
	if proxy.Port() == "" {
		host = net.JoinHostPort(proxy.Hostname(), "80")
	}
	nc, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", proxy.Redacted(), err)
	}
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u := proxy.User; u != nil {
		pw, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)))
	}
	br := bufio.NewReader(nc)
	err = req.Write(nc)
	var resp *http.Response
	if err == nil {
		resp, err = http.ReadResponse(br, req)
	}
	switch {
	case err != nil:
		err = fmt.Errorf("proxy %s: CONNECT %s: %w", proxy.Redacted(), addr, err)
	case resp.StatusCode != http.StatusOK:
		err = fmt.Errorf("proxy %s answered %s to CONNECT %s", proxy.Redacted(), resp.Status, addr)
	case br.Buffered() > 0: // the relay speaks only after the client
		err = fmt.Errorf("proxy %s: bytes after its answer to CONNECT %s", proxy.Redacted(), addr)
	}
	if err != nil || !stop() {
		_ = nc.Close()
		if err == nil {
			err = ctx.Err()
		}
		return nil, err
	}
	return nc, nil
}
