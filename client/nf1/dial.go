// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nf1

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/client/capaddr"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// Dial's errors for the relay's answers, each one exit code of the connect
// sidecar's table (the decision's section 6); a server that is not the
// address's is capaddr.ErrPin, ErrRendezvous or ErrTLS (7), a refused
// secret capaddr.ErrProof (10).
var (
	// ErrNotServed: no live agent serves the address at its relay (unknown,
	// offline, or the relay serves no nf1 addresses): exit 3.
	ErrNotServed = errors.New("nf1: no service at this address")
	// ErrRefused: the relay refused the open (a cap, its E2EE policy): exit 4.
	ErrRefused = errors.New("nf1: the relay refused the session")
	// ErrUnreachable: the relay was not reached or ended the connection: exit 5.
	ErrUnreachable = errors.New("nf1: relay unreachable")
	// ErrBalance: the serving account's balance is exhausted: exit 9.
	ErrBalance = errors.New("nf1: the serving account's balance is exhausted")
)

// Options are Dial's transport to the address's relay; the zero value
// dials it over TCP with the system's roots.
type Options struct {
	// TLSConfig is the TLS to the relay (nil: system roots, ServerName the
	// relay's host). Never the server's pin: that is the session's own TLS.
	TLSConfig *tls.Config
	// DialContext dials the relay (nil: net.Dialer).
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// window is a client data connection's window (one session).
const window = 1 << 20

// Dial opens a session to addr's service: at addr.Relay only, over an
// anonymous data connection, through the rendezvous, pinned TLS and the
// proof (Handshake). The conn's Close ends the data connection too.
func Dial(ctx context.Context, addr capaddr.Address, opt Options) (net.Conn, error) {
	relayAddr := addr.Relay
	if _, _, err := net.SplitHostPort(relayAddr); err != nil {
		relayAddr = net.JoinHostPort(addr.Relay, "443")
	}
	host, _, _ := net.SplitHostPort(relayAddr)
	dial := opt.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	nc, err := dial(ctx, "tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if opt.TLSConfig != nil {
		cfg = opt.TLSConfig.Clone()
	}
	tc := tls.Client(nc, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	done := bound(ctx, tc)
	mux, _, err := dataplane.Upgrade(ctx, tc, addr.Relay, "", window)
	done()
	if err != nil {
		_ = tc.Close()
		var nu *dataplane.NoUpgradeError
		if errors.As(err, &nu) && nu.Status == http.StatusUnauthorized {
			return nil, ErrNotServed // a relay that serves no nf1 addresses
		}
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	go func() { _ = mux.Serve(nil) }()
	s, err := mux.Open(&pb.TCPData{Nf1Rid: addr.RID[:], E2Ee: true, Answer: true})
	if err == nil {
		err = answerErr(s.Answered(ctx))
	}
	if err != nil {
		_ = mux.Close()
		return nil, err
	}
	c, err := Handshake(ctx, s, addr)
	if err != nil {
		_ = mux.Close()
		return nil, err
	}
	return &conn{Conn: c, mux: mux}, nil
}

// answerErr is the relay's answer to the open as Dial's error.
func answerErr(err error) error {
	if err == nil {
		return nil
	}
	var a *link.Abort
	var reason relayv1.ErrorReason
	ok := errors.As(err, &a)
	if ok {
		reason, ok = dataplane.AbortReason(a)
	}
	switch {
	case !ok:
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	case reason == relayv1.ErrorReason_ERROR_REASON_AGENT_OFFLINE, reason == relayv1.ErrorReason_ERROR_REASON_AGENT_NOT_FOUND, reason == relayv1.ErrorReason_ERROR_REASON_UNKNOWN_SERVICE:
		return fmt.Errorf("%w (%s)", ErrNotServed, a.Msg)
	case reason == relayv1.ErrorReason_ERROR_REASON_BALANCE_EXHAUSTED:
		return ErrBalance
	}
	return fmt.Errorf("%w: %s: %s", ErrRefused, reason, a.Msg)
}

// conn is a dialled session; Close ends its data connection.
type conn struct {
	net.Conn
	mux *dataplane.Mux
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	_ = c.mux.Close()
	return err
}
