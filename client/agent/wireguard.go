// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/metadata"
)

// WireGuardExit makes an agent a WireGuard exit (`nfltr wg serve`). The agent
// does not link WireGuard itself: package
// github.com/nfltr/relay/client/agent/wgexit provides an exit and its options
// (wgexit.WithWireGuard, WithWireGuardKeys, WithWireGuardPairingKeyFile), so
// only a program that imports it carries wireguard-go and gvisor.
type WireGuardExit interface {
	// Enabled reports whether the agent is an exit (a key is set); a pairing
	// key alone is not. An exit's tunnel packets go through one stream, so
	// an enabled exit does not move make-before-break off a leaving replica.
	Enabled() bool
	// ConnectMetadata adds the exit's connect metadata (its public key, the
	// end-to-end protocol, its flags).
	ConnectMetadata(md metadata.MD)
	// Start starts a tunnel from the relay's accept headers, replacing the
	// one of a previous connection. An error refuses the relay (one that
	// would terminate the tunnel); a nil tunnel and nil error mean no tunnel
	// this time (logged by the exit).
	Start(ctx context.Context, header metadata.MD, logger *slog.Logger) (WireGuardTunnel, error)
	// Close tears down the running tunnel, if any.
	Close()
}

// WireGuardTunnel is a running exit tunnel: the agent's receive loop moves its
// sealed packets and gives it the relay's PeerUpdates.
type WireGuardTunnel interface {
	// Handle takes a relay message for the tunnel: a sealed packet from a
	// client or a PeerUpdate. It reports whether msg was a WireGuard message.
	Handle(msg *pb.HTTPRequest) bool
	// Pump sends the tunnel's sealed packets to the relay until ctx ends or
	// send fails.
	Pump(ctx context.Context, send func(*pb.HTTPProxyResponse) error)
}

// WithWireGuardExit sets the agent's WireGuard exit. configure gets the exit
// set by earlier options (nil for none) and returns the one to use, so the
// wgexit options compose in any order; an error fails Connect. Programs use
// the wgexit options rather than this.
func WithWireGuardExit(configure func(WireGuardExit) (WireGuardExit, error)) Option {
	return func(a *agent) {
		x, err := configure(a.wgExit)
		if err != nil {
			a.initErr = err
			return
		}
		a.wgExit = x
	}
}

func (a *agent) wireGuardEnabled() bool { return a.wgExit != nil && a.wgExit.Enabled() }

// setWireGuardMetadata adds the WireGuard connect metadata.
func (a *agent) setWireGuardMetadata(md metadata.MD) {
	if a.wireGuardEnabled() {
		a.wgExit.ConnectMetadata(md)
	}
}

// startWireGuardFromHeader starts the tunnel from the relay's response
// headers. A relay without the end-to-end protocol is refused.
func (a *agent) startWireGuardFromHeader(ctx context.Context, header metadata.MD) error {
	if !a.wireGuardEnabled() || header.Len() == 0 {
		return nil // no WireGuard, or the relay refused the stream (processStream surfaces why)
	}
	tunnel, err := a.wgExit.Start(ctx, header, a.logger)
	if err != nil {
		return err
	}
	if tunnel != nil {
		a.wgx = tunnel
	}
	return nil
}

// closeWireGuard tears down the WG tunnel.
func (a *agent) closeWireGuard() {
	if a.wgExit != nil {
		a.wgExit.Close()
	}
}
