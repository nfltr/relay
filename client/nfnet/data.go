// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/client/relaytrust"
	"github.com/nfltr/relay/client/rpcclient"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"github.com/nfltr/relay/proto/wire/tlsbatch"
)

// The data connections: every session one of a few connections to the
// relay's HTTP port, upgraded to the TCP data plane: link sessions with
// per-session credit, half closes and resets, and link.FeatureChain: every
// open answered link's own way. Each 101 states the relay's E2EE policy
// (dataplane.E2EEPolicyHeader). A link.Pool holds them (link spec/Pool.tla):
// none until the first open, one more only when every one carries the
// relay's most sessions (1,024), at most maxDataConns. Guard:
// TestDialerPastOneConnectionsSessions.

// dataWindow is a session's window: what is queued for one local
// connection that reads slower than the relay sends.
const dataWindow = 4 << 20

// maxDataConns is how many data connections a Dialer holds at once: 4,096
// sessions at the relay's 1,024 per connection; past them an open fails
// (unreachable).
const maxDataConns = 4

// dataPool is the Dialer's Pool, made at the first use.
func (d *Dialer) dataPool() (*link.Pool, error) {
	d.poolOnce.Do(func() {
		d.pool, d.poolErr = link.NewPool(link.PoolConfig{
			Link: dataplane.ClientConfig(dataWindow),
			Dial: d.dialData,
			Max:  maxDataConns,
		})
	})
	return d.pool, d.poolErr
}

// openData opens a session on a data connection, dialling one when none
// takes it; an *Error when it cannot. ctx bounds the open and dial.
func (d *Dialer) openData(ctx context.Context, open *pb.TCPData) (*dataplane.Session, error) {
	header, err := dataplane.OpenHeader(open)
	if err != nil {
		return nil, unreachable(err)
	}
	p, err := d.dataPool()
	if err != nil {
		return nil, unreachable(err)
	}
	s, err := p.Open(ctx, header)
	if err != nil {
		return nil, dataError(ctx, err)
	}
	return s, nil
}

// dataError types a failed open or dial of a data connection.
func dataError(ctx context.Context, err error) error {
	if e, ok := errors.AsType[*Error](err); ok {
		return e
	}
	if nu, ok := errors.AsType[*dataplane.NoUpgradeError](err); ok {
		return openStatusError(nu.Status, "the relay refused the data connection")
	}
	if ctx.Err() != nil {
		return &Error{Code: CodeUnreachable, Message: "no answer from the relay within the open timeout: " + explainTLS(err).Error(), Err: err}
	}
	return unreachable(err)
}

func unreachable(err error) *Error {
	return &Error{Code: CodeUnreachable, Message: explainTLS(err).Error(), Err: err}
}

// openStatusError types the relay's refusal of a data connection.
func openStatusError(status int, body string) *Error {
	msg := strings.TrimSpace(body)
	if msg == "" {
		msg = http.StatusText(status)
	}
	e := &Error{Message: fmt.Sprintf("relay answered %d: %s", status, msg)}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.Code = CodeAuth
	case status == http.StatusPaymentRequired:
		e.Code = CodeBalanceExhausted
		e.Message += ": " + rpcclient.BalanceExhaustedHint
	case status == http.StatusNotFound:
		e.Code = CodeNotFound
	case status == http.StatusServiceUnavailable:
		e.Code = CodeRefused // TCP tunnelling is off on the relay
	case status >= 400 && status < 500:
		e.Code = CodeUsage
	default:
		e.Code = CodeUnreachable
	}
	return e
}

// explainTLS names the fingerprint of a relay certificate err refused, to
// pin it; any other error comes back unchanged.
func explainTLS(err error) error {
	cv, ok := errors.AsType[*tls.CertificateVerificationError](err)
	if !ok || len(cv.UnverifiedCertificates) == 0 {
		return err
	}
	fp := relaytrust.Fingerprint(cv.UnverifiedCertificates[0].Raw)
	return fmt.Errorf("%w (the relay's certificate is not trusted: if %s is your relay's certificate, pin it)", err, fp)
}

// E2EEPolicy is the relay's end-to-end encryption policy for TCP sessions
// ("require", "allow" or "forbid"), from its answer to a data connection:
// without one yet, a connection dialled for it alone and closed; ctx bounds
// that dial.
func (d *Dialer) E2EEPolicy(ctx context.Context) (string, error) {
	if p, ok := d.policy.Load().(string); ok {
		return p, nil
	}
	nc, err := d.dialData(ctx)
	if err == nil {
		var c *link.Conn
		if c, err = link.Client(ctx, nc, dataplane.ClientConfig(dataWindow)); err == nil {
			_ = c.Close()
		} else {
			_ = nc.Close()
		}
	}
	if err != nil {
		return "", dataError(ctx, err)
	}
	p, _ := d.policy.Load().(string)
	return p, nil
}

// dialData connects to the relay (TLS without ALPN: HTTP/1.1; plain TCP to
// a plaintext relay) and asks for the upgrade (the Pool's Dial; the Pool
// binds the link); it keeps the 101's E2EE policy. A refused machine
// certificate is an *Error CodeAuth.
func (d *Dialer) dialData(ctx context.Context) (net.Conn, error) {
	nc, err := d.dialRelay(ctx, d.cfg.Relay)
	if err != nil {
		return nil, err
	}
	key := d.cfg.APIKey
	if !d.cfg.Plaintext {
		cfg := d.relayTLS(d.cfg.Relay)
		if d.cfg.ClientCert != nil {
			get := d.cfg.ClientCert
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return get() }
		}
		tc := tlsbatch.Client(nc, cfg)
		if err := tc.Conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
			_ = tc.Close()
			return nil, d.certRefusal(err)
		}
		nc = tc
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(deadline)
	}
	hdr, err := dataplane.RequestUpgrade(nc, d.cfg.Relay, key)
	if err != nil && strings.HasPrefix(err.Error(), "malformed HTTP response") {
		// Not an HTTP server: most often the relay's gRPC port, which
		// answers with an HTTP/2 frame.
		err = fmt.Errorf("%s did not answer HTTP: Relay is the relay's HTTP address, not its gRPC address (grpc.<domain> is reached at <domain> by itself; a private relay serves HTTP on another port than gRPC)", d.cfg.Relay)
	}
	if err == nil {
		err = nc.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = nc.Close()
		return nil, d.certRefusal(err)
	}
	d.policy.Store(hdr.Get(dataplane.E2EEPolicyHeader))
	return nc, nil
}

// certRefusal types the relay's refusal of Config.ClientCert (a TLS alert,
// or 401/403 to the upgrade) as CodeAuth; other errors unchanged.
func (d *Dialer) certRefusal(err error) error {
	if d.cfg.ClientCert == nil {
		return err
	}
	refused := false
	if nu, ok := errors.AsType[*dataplane.NoUpgradeError](err); ok {
		refused = nu.Status == http.StatusUnauthorized || nu.Status == http.StatusForbidden
	} else if op, ok := errors.AsType[*net.OpError](err); ok && op.Op == "remote error" {
		refused = true // the relay's TLS alert to the certificate
	}
	if !refused {
		return err
	}
	return &Error{Code: CodeAuth, Message: "the relay refused this machine's certificate (revoked, rotated away or expired): " + err.Error(), Err: err}
}

// relayTLS is the TLS configuration for the relay at addr: RelayTLS's (or
// the system roots), its ServerName addr's host when unset.
func (d *Dialer) relayTLS(addr string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if d.cfg.RelayTLS != nil {
		cfg = d.cfg.RelayTLS.Clone()
	}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg.ServerName = host
	}
	return cfg
}

// dialRelay connects to a relay at addr: Config.DialRelay, else through
// the HTTP proxy the environment names for https://addr (HTTPS_PROXY,
// NO_PROXY), as a network whose only way out is its proxy needs, else
// directly.
func (d *Dialer) dialRelay(ctx context.Context, addr string) (net.Conn, error) {
	if d.cfg.DialRelay != nil {
		return d.cfg.DialRelay(ctx, addr)
	}
	p, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
	if err != nil {
		return nil, err
	}
	return dialThrough(ctx, p, addr)
}

// dialThrough connects to addr directly (proxy nil) or through an http://
// proxy's CONNECT, with Basic credentials from the proxy URL's user info.
// The connection is returned once the proxy answered 200: the bytes after
// it are addr's.
func dialThrough(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	d := &net.Dialer{}
	if proxy == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	if proxy.Scheme != "http" {
		return nil, fmt.Errorf("proxy %s: only an http:// proxy can carry the relay's sessions", proxy.Redacted())
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
