// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/tlsend"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// Sessions to a capability address (nf1..., nfltr
// docs/decisions/nf1-rendezvous-2026-11-13.md): at the address's relay
// only, over a data connection of their own with no credential, through the
// agent's rendezvous answer, TLS pinned to the address and the secret's
// proof (nf1.ClientTLS). With DialOptions.Direct the session is framed for
// direct paths when the listener's signed answer says it takes them
// (nf1-direct). Its errors are the rendezvous decision's section 6. An nf1
// dial waits for its answer (Early does not apply: the handshake needs
// it) and is always end-to-end encrypted.

// dialNF1 opens one session to t's address.
func (d *Dialer) dialNF1(ctx context.Context, t Target, o DialOptions) (*Conn, error) {
	if o.Plain {
		return nil, usage("an nf1 address is always end-to-end encrypted: Plain does not apply")
	}
	addr := t.Address
	ls, mux, err := d.nf1Open(ctx, addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = mux.Close() })
	fail := func(err error) (*Conn, error) {
		stop()
		d.dropMux(mux)
		return nil, err
	}
	hints, err := nf1.ReadAnswer(ls, addr)
	if err != nil {
		return fail(handshakeError(ctx, err))
	}
	c := d.newConn(t, traceOf(ls))
	c.closers = append(c.closers, func() { d.dropMux(mux) })
	raw, done := net.Conn(ls), ls.Done()
	if o.Direct != DirectOff {
		if !nf1.TakesDirect(hints) {
			c.onPath(agent.PathEvent{Path: agent.PathRelayed, Reason: agent.ReasonOff})
		} else if dc, err := d.nf1Direct(addr); err != nil {
			c.onPath(agent.PathEvent{Path: agent.PathRelayed, Reason: "no_socket"})
		} else {
			c.ds = dc.Start(ls)
			raw, done = c.ds.Conn(), c.ds.Done()
		}
	}
	w, bind := tlsend.Wrap(raw)
	tc, err := nf1.ClientTLS(ctx, w, addr)
	if err != nil {
		return fail(handshakeError(ctx, err))
	}
	if !stop() { // ctx ended as the session opened
		return fail(handshakeError(ctx, ctx.Err()))
	}
	c.tc = bind(tc)
	c.s, c.done = c.tc, done
	if c.ds != nil {
		route := agent.NF1Route{Addr: addr, Open: d.nf1Relayed(addr)}
		if err := c.ds.RunNF1(tc.ConnectionState(), route, o.Direct, c.onPath); err != nil {
			c.onPath(agent.PathEvent{Path: agent.PathRelayed, Reason: "no_exporter"})
		}
	}
	return c, nil
}

// nf1Open opens a session to the address on a data connection of its own,
// answered by the relay; the Dialer owns the connection until dropMux.
func (d *Dialer) nf1Open(ctx context.Context, addr capaddr.Address) (*dataplane.Session, *dataplane.Mux, error) {
	mux, err := d.nf1Upgrade(ctx, addr)
	if err != nil {
		return nil, nil, err
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = mux.Close()
		return nil, nil, errClosed
	}
	d.nf1Muxs[mux] = struct{}{}
	d.mu.Unlock()
	go func() { _ = mux.Serve(nil) }()
	ls, err := mux.Open(&pb.TCPData{Nf1Rid: addr.RID[:], E2Ee: true, Answer: true})
	if err == nil {
		err = answered(ctx, ls)
		if e, ok := errors.AsType[*Error](err); ok && e.Reason == relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE.String() {
			e.Code, e.Message = CodeRefused, "the relay does not allow end-to-end encrypted sessions: "+e.Message
		}
	}
	if err != nil {
		d.dropMux(mux)
		return nil, nil, err
	}
	return ls, mux, nil
}

// dropMux ends an nf1 session's data connection.
func (d *Dialer) dropMux(m *dataplane.Mux) {
	_ = m.Close()
	d.mu.Lock()
	delete(d.nf1Muxs, m)
	d.mu.Unlock()
}

// nf1Relayed is the direct paths' way to the address (agent.NF1Route): a
// session whose Close ends its data connection.
func (d *Dialer) nf1Relayed(addr capaddr.Address) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		ls, mux, err := d.nf1Open(ctx, addr)
		if err != nil {
			return nil, err
		}
		return muxConn{Session: ls, end: func() { d.dropMux(mux) }}, nil
	}
}

// muxConn is a session whose Close ends its own data connection.
type muxConn struct {
	*dataplane.Session
	end func()
}

func (c muxConn) Close() error {
	err := c.Session.Close()
	c.end()
	return err
}

// nf1Direct is the direct paths to addresses at addr's relay, made at the
// first session that asks: no identity of this machine's (the address's
// secret admits it), QAD at the address's relay.
func (d *Dialer) nf1Direct(addr capaddr.Address) (*agent.DirectClient, error) {
	hostport := d.nf1HostPort(addr)
	return d.directClient(hostport, func() (*agent.DirectClient, error) {
		return agent.NewDirectClient(agent.DirectClientConfig{
			QADTLS: func(string) *tls.Config { return d.nf1TLS(hostport) },
			OwnQAD: hostport,
		})
	})
}

// nf1HostPort is the address's relay with its port (443, or 80 for a
// plaintext relay, when it names none).
func (d *Dialer) nf1HostPort(addr capaddr.Address) string {
	if _, _, err := net.SplitHostPort(addr.Relay); err == nil {
		return addr.Relay
	}
	port := "443"
	if d.cfg.Plaintext {
		port = "80"
	}
	return net.JoinHostPort(addr.Relay, port)
}

// nf1TLS verifies the address's relay: Config.RelayTLS when it is
// Config.Relay (or no Relay is set), else the system roots. The session's
// security rests on the pin and the proof, not on it.
func (d *Dialer) nf1TLS(hostport string) *tls.Config {
	if d.cfg.Relay == "" || sameRelay(hostport, d.cfg.Relay) {
		return d.relayTLS(hostport)
	}
	host, _, _ := net.SplitHostPort(hostport)
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
}

// sameRelay: a and b name one relay; the HTTPS port 443 is the same as
// none.
func sameRelay(a, b string) bool {
	norm := func(s string) string { return strings.ToLower(strings.TrimSuffix(s, ":443")) }
	return norm(a) == norm(b)
}

// nf1Upgrade makes a data connection to the address's relay with no
// credential.
func (d *Dialer) nf1Upgrade(ctx context.Context, addr capaddr.Address) (*dataplane.Mux, error) {
	hostport := d.nf1HostPort(addr)
	unreachable := func(err error) error {
		return &Error{Code: CodeUnreachable, Message: fmt.Sprintf("relay %s: %v", addr.Relay, err), Err: errors.Join(nf1.ErrUnreachable, err)}
	}
	nc, err := d.dialRelay(ctx, hostport)
	if err != nil {
		return nil, unreachable(err)
	}
	if !d.cfg.Plaintext {
		tc := tls.Client(nc, d.nf1TLS(hostport))
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = nc.Close()
			return nil, unreachable(err)
		}
		nc = tc
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	}
	mux, _, err := dataplane.Upgrade(ctx, nc, addr.Relay, "", dataWindow)
	_ = nc.SetDeadline(time.Time{})
	if err == nil {
		return mux, nil
	}
	_ = nc.Close()
	nu, ok := errors.AsType[*dataplane.NoUpgradeError](err)
	switch {
	case ok && nu.Status == http.StatusUnauthorized: // a relay that serves no nf1 addresses
		return nil, &Error{Code: CodeNotFound, Message: "no nf1 service at this address (the relay serves no capability addresses)", Err: nf1.ErrNotServed}
	case ok && nu.Status == http.StatusTooManyRequests:
		return nil, &Error{Code: CodeRefused, Message: "the relay refused: too many connections from this address", Err: nf1.ErrRefused}
	}
	return nil, unreachable(err)
}

// handshakeError is the *Error of the rendezvous answer's or nf1.ClientTLS's
// error.
func handshakeError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, capaddr.ErrPin), errors.Is(err, capaddr.ErrRendezvous), errors.Is(err, capaddr.ErrTLS), errors.Is(err, nf1.ErrAnswer):
		return &Error{Code: CodeE2EEPinMismatch, Message: "the server is not this address's: " + err.Error(), Err: err}
	case errors.Is(err, capaddr.ErrProof):
		return &Error{Code: CodeE2EEClientRefused, Message: "the server refused this address's secret (it serves another address now, or the address was replaced)", Err: err}
	case ctx.Err() != nil:
		return &Error{Code: CodeUnreachable, Message: "no nf1 handshake within the open timeout", Err: ctx.Err()}
	}
	return &Error{Code: CodeReset, Message: "the session ended during the nf1 handshake: " + err.Error(), Err: err}
}
