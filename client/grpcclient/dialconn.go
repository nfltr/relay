// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"context"
	"crypto/tls"
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
// tunnel's data connection (pkg/agent RelayDialer). gRPC dials through an
// HTTPS proxy from the environment and this does not, so it fails when one
// is set for the relay, and the tunnel stays on gRPC.
func DialConn(ctx context.Context, secure bool, tlsCfg *tls.Config, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if p, _ := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}}); p != nil {
		return nil, fmt.Errorf("relay %s is reached through proxy %s", addr, p.Redacted())
	}
	nc, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
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
