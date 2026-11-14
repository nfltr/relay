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

// Options are Dial's transport to the address's relay.
type Options struct {
	// DialRelay connects to the address's relay (its host and port) and
	// returns the connection with its TLS done; nil: TCP to the relay
	// (port 443 when it names none) and TLS with the system's roots. The
	// session's security does not rest on it (the pin and the proof do:
	// every relay is untrusted); it keeps the rendezvous id from the
	// network.
	DialRelay func(ctx context.Context, relay string) (net.Conn, error)
}

// window is a client data connection's window (one session).
const window = 1 << 20

// dialRelay is Options.DialRelay's default.
func dialRelay(ctx context.Context, relay string) (net.Conn, error) {
	addr := relay
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(relay, "443")
	}
	host, _, _ := net.SplitHostPort(addr)
	nc, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(nc, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = nc.Close()
		return nil, err
	}
	return tc, nil
}

// Dial opens a session to addr's service: at addr.Relay only, over an
// anonymous data connection, through the rendezvous, pinned TLS and the
// proof (Handshake). The conn's Close ends the data connection too; it
// has CloseWrite, the TLS session's half close.
func Dial(ctx context.Context, addr capaddr.Address, opt Options) (net.Conn, error) {
	dial := opt.DialRelay
	if dial == nil {
		dial = dialRelay
	}
	tc, err := dial(ctx, addr.Relay)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	done := bound(ctx, tc)
	mux, _, err := dataplane.Upgrade(ctx, tc, addr.Relay, "", window)
	done()
	if err != nil {
		_ = tc.Close()
		var nu *dataplane.NoUpgradeError
		switch {
		case errors.As(err, &nu) && nu.Status == http.StatusUnauthorized:
			return nil, ErrNotServed // a relay that serves no nf1 addresses
		case errors.As(err, &nu) && nu.Status == http.StatusTooManyRequests:
			return nil, fmt.Errorf("%w: too many connections from this address", ErrRefused)
		}
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	go func() { _ = mux.Serve(nil) }()
	s, err := mux.Open(&pb.TCPData{Nf1Rid: addr.RID[:], E2Ee: true, Answer: true})
	if err != nil {
		_ = mux.Close()
		return nil, answerErr(err)
	}
	if err := answerErr(s.Answered(ctx)); err != nil {
		_ = s.Close()
		_ = mux.Close()
		return nil, err
	}
	c, err := Handshake(ctx, s, addr)
	if err != nil {
		_ = mux.Close()
		return nil, err
	}
	return &conn{Conn: c.(*tls.Conn), mux: mux}, nil
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

// conn is a dialled session; Close ends its data connection. The
// embedded TLS connection's CloseWrite is the session's half close
// (close_notify: the server reads EOF, its bytes still arrive).
type conn struct {
	*tls.Conn
	mux *dataplane.Mux
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	_ = c.mux.Close()
	return err
}
