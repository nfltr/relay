// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// The relay dial (gRPC, the data plane) is native only: a js/wasm build of
// this package is the handshake alone (nfltr
// docs/decisions/browser-peer-2026-11-16.md, lane BP1; make wasm-nf1).

//go:build !js

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
	"github.com/nfltr/relay/client/tlsend"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
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
	// Datagram dials the address's datagram service (its answer must say
	// it serves datagrams: ErrKind otherwise); the session's bytes are then
	// an association's (client/dgram).
	Datagram bool
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
// has CloseWrite, the TLS session's half close, and Reset; a relay's cut
// reads as tlsend.ErrTruncated, never io.EOF.
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
	// The ClientHello goes with the open; the answers are taken before TLS
	// reads (AnswerConn).
	ac := EarlyAnswer(s, addr, opt.Datagram, func() error { return answerErr(s.Answered(ctx)) })
	w, bind := tlsend.Wrap(ac)
	done = bound(ctx, w)
	c, err := ClientTLS(ctx, w, addr)
	done()
	if err != nil && ac.Err() != nil {
		err = ac.Err()
	}
	if errors.Is(err, ErrDirectRequired) {
		_ = AbortDirectRequired(s)
	}
	if err != nil {
		_ = s.Close()
		_ = mux.Close()
		return nil, err
	}
	return &conn{Conn: bind(c), mux: mux}, nil
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
	case reason == relayv1.ErrorReason_ERROR_REASON_ACCOUNT_REQUIRED:
		return fmt.Errorf("%w (%s)", ErrDirectRequired, a.Msg)
	}
	return fmt.Errorf("%w: %s: %s", ErrRefused, reason, a.Msg)
}

// conn is a dialled session; Close ends its data connection. The
// embedded TLS connection's CloseWrite is the session's half close
// (close_notify: the server reads EOF, its bytes still arrive); its Read
// returns tlsend.ErrTruncated, never io.EOF, when the session ends
// without the server's close_notify (a relay's cut); Reset ends it as
// failed (no close_notify).
type conn struct {
	*tlsend.Conn
	mux *dataplane.Mux
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	_ = c.mux.Close()
	return err
}

func (c *conn) Reset() error {
	err := c.Conn.Reset()
	_ = c.mux.Close()
	return err
}

// AbortDirectRequired ends c, a session to or of an address served with
// no account, as relay ERROR_REASON_ACCOUNT_REQUIRED when it is a link
// session (the relay passes the ABORT on, so the other end reads the same
// reason; nfltr docs/decisions/nf1-anon-2026-11-16.md section 2), else
// resets or closes it.
func AbortDirectRequired(c net.Conn) error {
	switch v := c.(type) {
	case interface{ Abort(uint32, string) error }:
		return v.Abort(dataplane.AbortCode(relayv1.ErrorReason_ERROR_REASON_ACCOUNT_REQUIRED), ErrDirectRequired.Error())
	case interface{ Reset() error }:
		return v.Reset()
	}
	return c.Close()
}
