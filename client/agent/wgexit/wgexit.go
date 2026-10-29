// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package wgexit makes a relay agent a WireGuard exit (`nfltr wg serve`). It
// is separate from package agent so that only programs that run an exit link
// wireguard-go and the gvisor netstack:
//
//	a := agent.New(cfg,
//		wgexit.WithWireGuard([]string{"192.168.1.0/24"}),
//		wgexit.WithWireGuardPairingKeyFile("pairing.key"),
//	)
package wgexit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/wg"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/wgwire"
	"google.golang.org/grpc/metadata"
)

// exit is an agent's WireGuard exit configuration and its running tunnel.
type exit struct {
	privateKey   string               // base64 WG private key
	publicKey    string               // base64 WG public key (derived)
	presharedKey string               // base64 pairing-derived preshared key, or ""
	allow        wg.DestinationPolicy // destinations this agent forwards to
	isExitNode   bool                 // advertise as an exit (`nfltr wg serve`)

	running *tunnel // the tunnel of the current connection, or nil
}

var _ agent.WireGuardExit = (*exit)(nil)

// errRelayTooOld is returned when the relay answers without the end-to-end
// protocol: it would terminate the tunnel, so the agent refuses it.
var errRelayTooOld = errors.New("agent: the relay does not run end-to-end WireGuard (" + wgwire.ProtocolHeader + ": " + wgwire.Protocol + "); it would terminate the tunnel: upgrade the relay")

// parseAllow parses the destinations a WireGuard agent forwards to: CIDRs, IPs
// or hostnames, each optionally with ":port", or "all". An empty list is an
// error: the agent never forwards anywhere by default.
// allow:wrapper — binds the system resolver once for the three WG options.
func parseAllow(allow []string) (wg.DestinationPolicy, error) {
	return wg.ParseDestinationPolicy(allow, func(host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	})
}

// configure returns an agent option that updates the exit set by earlier
// options (or a new one) with set.
func configure(set func(*exit) error) agent.Option {
	return agent.WithWireGuardExit(func(prev agent.WireGuardExit) (agent.WireGuardExit, error) {
		return update(prev, set)
	})
}

// update applies set to a copy of prev's exit (a new one if prev is not one).
func update(prev agent.WireGuardExit, set func(*exit) error) (agent.WireGuardExit, error) {
	x := &exit{}
	if p, ok := prev.(*exit); ok && p != nil {
		c := *p
		x = &c
	}
	if err := set(x); err != nil {
		return prev, err
	}
	return x, nil
}

// The options' setters, applied by update (and the tests).
func generateKeys(allow []string) func(*exit) error {
	return func(x *exit) error {
		privKey, _, err := wg.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("WithWireGuard: key generation failed: %w", err)
		}
		return x.setKeys("WithWireGuard", privKey, allow)
	}
}

func useKeys(privateKeyB64 string, allow []string) func(*exit) error {
	return func(x *exit) error { return x.setKeys("WithWireGuardKeys", privateKeyB64, allow) }
}

func pairingKeyFile(path string) func(*exit) error {
	return func(x *exit) error {
		psk, err := wg.PresharedKeyFromFile(path)
		if err != nil {
			return fmt.Errorf("WithWireGuardPairingKeyFile: %w", err)
		}
		x.presharedKey = psk
		return nil
	}
}

// WithWireGuard makes the agent a WireGuard exit (`nfltr wg serve`). The agent
// generates a key pair and sends its public key on connect; the relay assigns
// a CGNAT IP and later tells the agent which client keys to peer with. The
// clients' tunnels end at this agent (gvisor netstack, userspace, no root):
// the relay forwards only sealed packets.
//
// allow lists the destinations reachable through the tunnel (CIDR, IP or
// hostname, each optionally ":port"; "all" for everything). It is required.
func WithWireGuard(allow []string) agent.Option {
	return configure(generateKeys(allow))
}

// WithWireGuardKeys is WithWireGuard with a pre-existing base64 private key,
// so clients see the same exit key across agent restarts.
func WithWireGuardKeys(privateKeyB64 string, allow []string) agent.Option {
	return configure(useKeys(privateKeyB64, allow))
}

// WithWireGuardPairingKeyFile mixes a pairing key (--e2ee-key-file, the same
// file on every client) into each client handshake, so a relay that swaps in
// its own key cannot complete one. Clients must use the same file. It has
// no effect without WithWireGuard or WithWireGuardKeys.
func WithWireGuardPairingKeyFile(path string) agent.Option {
	return configure(pairingKeyFile(path))
}

func (x *exit) setKeys(option, privKey string, allow []string) error {
	policy, err := parseAllow(allow)
	if err != nil {
		return fmt.Errorf("%s: %w", option, err)
	}
	pubKey, err := wg.PublicKeyFromPrivate(privKey)
	if err != nil {
		return fmt.Errorf("%s: invalid private key: %w", option, err)
	}
	x.privateKey, x.publicKey, x.allow, x.isExitNode = privKey, pubKey, policy, true
	return nil
}

func (x *exit) Enabled() bool { return x.privateKey != "" }

// ConnectMetadata adds the WireGuard connect metadata.
func (x *exit) ConnectMetadata(md metadata.MD) {
	md.Set("x-wg-pubkey", x.publicKey)
	md.Set(wgwire.ProtocolHeader, wgwire.Protocol)
	if x.isExitNode {
		md.Set("x-wg-exit-node", "true")
	}
	if x.presharedKey != "" {
		md.Set(wgwire.PairedHeader, "true")
	}
}

// Start starts the tunnel from the relay's response headers. A relay without
// the end-to-end protocol is refused.
func (x *exit) Start(ctx context.Context, header metadata.MD, logger *slog.Logger) (agent.WireGuardTunnel, error) {
	if v := header.Get(wgwire.ProtocolHeader); len(v) == 0 || v[0] != wgwire.Protocol {
		return nil, errRelayTooOld
	}
	ips := header.Get("x-wg-assigned-ip")
	if len(ips) == 0 || ips[0] == "" {
		logger.Warn("relay assigned no WireGuard address")
		return nil, nil
	}
	assignedIP, err := netip.ParseAddr(ips[0])
	if err != nil {
		logger.Warn("invalid wg assigned IP from server", "ip", ips[0], "error", err)
		return nil, nil
	}
	t, err := x.start(ctx, assignedIP, logger)
	if err != nil {
		logger.Error("wireguard tunnel setup failed", "error", err)
		return nil, nil
	}
	return t, nil
}

// start creates the exit tunnel on the assigned CGNAT IP, with no peer yet:
// the relay adds each client it vouches for (tunnel.Handle). A forwarding
// tunnel proxies tunnel traffic to the --allow destinations.
func (x *exit) start(ctx context.Context, assignedIP netip.Addr, logger *slog.Logger) (*tunnel, error) {
	logger = logger.With("subsystem", "wireguard")
	tunnelCfg := wg.TunnelConfig{
		PrivateKey:   x.privateKey,
		PresharedKey: x.presharedKey,
		LocalAddress: assignedIP,
		MTU:          1420,
	}

	// Close any previous WG tunnel from a prior connection cycle
	// to prevent goroutine/channel leaks.
	x.Close()

	bind := wg.NewRelayBind()
	t := wg.NewForwardingTunnel(logger, x.allow)
	if err := t.Start(ctx, tunnelCfg, bind); err != nil {
		return nil, err
	}
	logger.Info("wireguard tunnel active",
		"local_ip", assignedIP.String(),
		"public_key", x.publicKey,
		"paired", x.presharedKey != "",
		"allow", x.allow.String())
	x.running = &tunnel{bind: bind, tunnel: t, logger: logger}
	return x.running, nil
}

// Close tears down the WG tunnel.
func (x *exit) Close() {
	if x.running != nil {
		_ = x.running.tunnel.Close()
	}
}

// tunnel is a running exit tunnel: the agent's receive loop moves its sealed
// packets and applies the relay's PeerUpdates to it.
type tunnel struct {
	bind   *wg.RelayBind
	tunnel wg.Tunnel
	logger *slog.Logger

	// reportFailedHandshake's rate limit; Handle runs on the stream's one
	// receive loop, so no lock.
	failedLoggedAt   time.Time
	failedSuppressed int
}

var _ agent.WireGuardTunnel = (*tunnel)(nil)

// Handle takes a relay message for the tunnel: a sealed packet from a client
// (tagged with the client's key) or a PeerUpdate. It reports whether msg was
// a WireGuard message.
func (w *tunnel) Handle(msg *pb.HTTPRequest) bool {
	switch txn := msg.GetTransactionId(); {
	case txn == wgwire.PeerTxnID:
		u, err := wgwire.ParsePeerUpdate(msg.Payload)
		if err != nil {
			w.logger.Warn("wg: rejected peer update from the relay", "error", err)
			return true
		}
		if u.Op == wgwire.PeerAdd {
			err = w.tunnel.AddPeer(u.PublicKey, u.IP)
		} else {
			w.reportFailedHandshake(u.PublicKey)
			err = w.tunnel.RemovePeer(u.PublicKey)
		}
		if err != nil {
			w.logger.Warn("wg: peer update failed", "op", u.Op, "error", err)
		} else {
			w.logger.Info("wg: client peer "+u.Op, "public_key", u.PublicKey, "ip", u.IP)
		}
		return true
	case wgwire.IsPacketTxnID(txn):
		peer, _ := wgwire.ExitPacketPeer(txn)
		if err := w.bind.Deliver(peer, msg.Payload); err != nil {
			w.logger.Warn("wg relay deliver failed", "error", err)
		}
		return true
	}
	return false
}

// failedHandshakeLogEvery bounds the failed-handshake warning: a client that
// reconnects in a loop with the wrong pairing key logs once per interval, the
// next line counting the ones left out.
var failedHandshakeLogEvery = time.Minute

// reportFailedHandshake warns about a client the relay is removing whose
// handshake messages arrived but never completed one: with pairing keys, a
// mismatched --e2ee-key-file. It asks when the client leaves, not on a timer:
// the client gives up after its own bound and a longer exit watch ended
// silently once the peer was gone (R4-G12). The line carries no key;
// the "client peer remove" line that follows names the client.
func (w *tunnel) reportFailedHandshake(peer string) {
	st, err := w.tunnel.PeerStatus(peer)
	if err != nil || !st.HandshakeFailed() {
		return
	}
	if now := time.Now(); w.failedLoggedAt.IsZero() || now.Sub(w.failedLoggedAt) >= failedHandshakeLogEvery {
		w.logger.Warn("wg: a client left without completing a WireGuard handshake; its --e2ee-key-file probably does not match this exit's",
			"suppressed_since_last", w.failedSuppressed)
		w.failedLoggedAt, w.failedSuppressed = now, 0
		return
	}
	w.failedSuppressed++
}

// Pump sends the tunnel's sealed packets to the relay, each tagged with the
// client it is for, until ctx ends or send fails.
func (w *tunnel) Pump(ctx context.Context, send func(*pb.HTTPProxyResponse) error) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-w.bind.Outbound():
			if !ok {
				return
			}
			if err := send(&pb.HTTPProxyResponse{Response: &pb.HTTPResponse{TransactionId: wgwire.ExitPacketTxnID(pkt.Peer), Payload: pkt.Data}}); err != nil {
				w.logger.Warn("wg relay send failed", "error", err)
				return
			}
		}
	}
}
