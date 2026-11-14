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
	go func() {
		_ = dgram.Serve(ctx, assoc, dgram.Config{}, func() (net.Conn, error) { return net.DialUDP("udp", nil, addr) })
	}()
	return session, 0, nil
}
