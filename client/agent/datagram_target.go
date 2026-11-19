// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net"

	"github.com/nfltr/relay/client/dgram"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
)

// dialDatagram serves a udp service's session, an association
// (client/dgram): its target resolved once, each flow a connected UDP
// socket of its own. The session's bytes go to the returned end of a pipe
// whose other end dgram.Serve reads; the association ends with the session
// (the pipe's close) or ctx.
func dialDatagram(ctx context.Context, target string) (net.Conn, relayv1.ErrorReason, error) {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, relayv1.ErrorReason_ERROR_REASON_TARGET_UNREACHABLE, err
	}
	session, assoc := net.Pipe()
	s := dgram.NewServer(assoc, dgram.Config{}, func() (net.Conn, error) { return net.DialUDP("udp", nil, addr) })
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	go func() { <-s.Done(); stop() }()
	return datagramTarget{Conn: session, srv: s}, 0, nil
}

// datagramTarget is a udp service's session end: its association's
// server, which takes the session's direct path once the session is
// framed for one (setDirect).
type datagramTarget struct {
	net.Conn
	srv *dgram.Server
}

// revokeDatagrams ends target's association for a revocation when target
// is a udp service's session end: nothing reaches its target from now on,
// each open flow's client is told why (dgram.ReasonRevoked: flow_close
// "revoked", not "reset", lane UDPFIX) on the session, and the session
// ends cleanly after it. False, target untouched, for any other target.
func revokeDatagrams(target net.Conn) bool {
	t, ok := target.(datagramTarget)
	if ok {
		t.srv.CloseWith(dgram.ReasonRevoked)
	}
	return ok
}

// setDirect gives target's association (a udp service's) the direct
// datagrams of its session s; any other target, or none, is left as it is.
func setDirect(target net.Conn, s *directSession) {
	if q, ok := target.(*QueueConn); ok && s != nil {
		cut := func() { s.tr.targetReset(); s.reset() }
		q.cut.Store(&cut)
	}
	if t, ok := target.(datagramTarget); ok && s != nil {
		t.srv.SetDirect(s.dg)
		s.revoke.Store(t.srv)
	}
}
