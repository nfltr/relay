// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Sentinel errors.
var (
	ErrTunnelClosed   = errors.New("wg: tunnel is closed")
	ErrAlreadyStarted = errors.New("wg: tunnel already started")
)

// TunnelConfig holds the parameters needed to create a WireGuard tunnel.
type TunnelConfig struct {
	// PrivateKey is this endpoint's WireGuard private key (base64-encoded).
	PrivateKey string

	// PeerPublicKey is the remote peer's WireGuard public key (base64-encoded).
	// A client's peer is its exit. An exit starts with no peer (empty) and
	// adds a peer per client with AddPeer.
	PeerPublicKey string

	// PresharedKey (base64), when set, is mixed into every peer's handshake
	// (PresharedKeyFromFile): a relay that swaps in its own public key
	// cannot complete a handshake without it.
	PresharedKey string

	// LocalAddress is the CGNAT IP assigned to this endpoint (e.g. 100.64.0.1).
	LocalAddress netip.Addr

	// AllowedIPs are the IP prefixes that should be routed through the tunnel
	// to PeerPublicKey.
	AllowedIPs []netip.Prefix

	// MTU is the tunnel interface MTU. Default: 1420 (WireGuard standard).
	MTU int

	// DNS are the DNS servers reachable through the tunnel.
	DNS []netip.Addr
}

// Tunnel is the interface for a userspace WireGuard tunnel.
type Tunnel interface {
	// Start creates the WireGuard device and configures the peer.
	Start(ctx context.Context, cfg TunnelConfig, bind *RelayBind) error

	// Net returns the gvisor netstack networking stack that routes through
	// the WireGuard tunnel.
	Net() *netstack.Net

	// AddPeer adds (or updates) a peer whose only AllowedIP is ip. An exit
	// adds each client the relay vouches for.
	AddPeer(publicKey string, ip netip.Addr) error

	// RemovePeer removes a peer.
	RemovePeer(publicKey string) error

	// Rehandshake drops the current session with a peer and starts a new
	// handshake at once. A client calls it after a reconnect: the exit may
	// have forgotten the session (the relay removed and re-added the
	// client's key) and would drop the client's packets until WireGuard
	// rehandshakes on its own after about 15s without an answer.
	Rehandshake(publicKey string) error

	// PeerStatus reports a peer's last completed handshake and bytes
	// received (AwaitHandshake, PeerStatus.HandshakeFailed).
	PeerStatus(publicKey string) (PeerStatus, error)

	// Close tears down the tunnel device and releases resources.
	Close() error
}

// NewTunnel creates a new userspace WireGuard tunnel.
func NewTunnel(logger *slog.Logger) Tunnel {
	if logger == nil {
		logger = slog.Default()
	}
	return &netstackTunnel{logger: logger}
}

type netstackTunnel struct {
	logger *slog.Logger
	mu     sync.Mutex
	dev    *device.Device
	psk    string
	tnet   *netstack.Net
	closed bool
}

// Start creates the gvisor TUN device, configures WireGuard, and brings the
// device up.
func (t *netstackTunnel) Start(_ context.Context, cfg TunnelConfig, bind *RelayBind) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.dev != nil {
		return ErrAlreadyStarted
	}
	if t.closed {
		return ErrTunnelClosed
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1420
	}

	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{cfg.LocalAddress},
		cfg.DNS,
		mtu,
	)
	if err != nil {
		return fmt.Errorf("wg: create netstack TUN: %w", err)
	}

	// netstack.CreateNetTUN eagerly sends tun.EventUp into the TUN's
	// buffered event channel.  device.NewDevice starts a goroutine
	// (RoutineTUNEventReader) that reads from this channel and calls
	// device.Up().  If our explicit dev.Up() below races with that
	// goroutine's Up(), we get a double BindUpdate (Close→Open→Close→Open)
	// that can leave the RelayBind in a dirty state, surfacing
	// "use of closed network connection".
	//
	// Drain the premature EventUp so that only our explicit dev.Up()
	// (called after IpcSet configures the peer) brings the device up.
	select {
	case <-tunDev.Events():
	default:
	}

	wgLogger := device.NewLogger(device.LogLevelSilent, "wg: ")
	if t.logger.Enabled(context.Background(), slog.LevelDebug) {
		wgLogger = device.NewLogger(device.LogLevelVerbose, "wg: ")
	}

	dev := device.NewDevice(tunDev, bind, wgLogger)

	ipcConf, err := buildIPC(cfg)
	if err != nil {
		dev.Close()
		return err
	}
	if err := dev.IpcSet(ipcConf); err != nil {
		dev.Close()
		return fmt.Errorf("wg: ipc set: %w", err)
	}

	t.dev = dev
	t.psk = cfg.PresharedKey
	t.tnet = tnet

	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wg: device up: %w", err)
	}

	t.logger.Info("wg: tunnel started",
		"local_addr", cfg.LocalAddress,
		"mtu", mtu,
	)

	return nil
}

func (t *netstackTunnel) AddPeer(publicKey string, ip netip.Addr) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return addPeer(t.dev, t.psk, publicKey, ip)
}

func (t *netstackTunnel) RemovePeer(publicKey string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return removePeer(t.dev, publicKey)
}

func (t *netstackTunnel) Rehandshake(publicKey string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return rehandshake(t.dev, publicKey)
}

func (t *netstackTunnel) PeerStatus(publicKey string) (PeerStatus, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return peerStatus(t.dev, publicKey)
}

// Net returns the gvisor netstack for dialing through the tunnel.
func (t *netstackTunnel) Net() *netstack.Net {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tnet
}

// Close tears down the WireGuard device.
func (t *netstackTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
		t.logger.Info("wg: tunnel closed")
	}
	return nil
}

// NewForwardingTunnel creates a WireGuard tunnel that intercepts all incoming
// TCP connections and forwards them to the real network. This is used by the
// "wg serve" agent to act as an exit node — traffic arriving through the tunnel
// is proxied to the agent's LAN without needing explicit port listeners.
//
// allow is the set of destinations the tunnel forwards to.
func NewForwardingTunnel(logger *slog.Logger, allow DestinationPolicy) Tunnel {
	if logger == nil {
		logger = slog.Default()
	}
	return &forwardingTunnel{logger: logger, allow: allow}
}

type forwardingTunnel struct {
	logger *slog.Logger
	allow  DestinationPolicy
	mu     sync.Mutex
	dev    *device.Device
	psk    string
	tunDev *forwardTUN
	closed bool
}

func (t *forwardingTunnel) Start(_ context.Context, cfg TunnelConfig, bind *RelayBind) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.dev != nil {
		return ErrAlreadyStarted
	}
	if t.closed {
		return ErrTunnelClosed
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1420
	}

	fwdTUN, err := CreateForwardingTUN(cfg.LocalAddress, mtu, t.allow, t.logger)
	if err != nil {
		return fmt.Errorf("wg: create forwarding TUN: %w", err)
	}

	wgLogger := device.NewLogger(device.LogLevelSilent, "wg: ")
	if t.logger.Enabled(context.Background(), slog.LevelDebug) {
		wgLogger = device.NewLogger(device.LogLevelVerbose, "wg: ")
	}

	dev := device.NewDevice(fwdTUN, bind, wgLogger)

	ipcConf, err := buildIPC(cfg)
	if err != nil {
		dev.Close()
		return err
	}
	if err := dev.IpcSet(ipcConf); err != nil {
		dev.Close()
		return fmt.Errorf("wg: ipc set: %w", err)
	}

	t.dev = dev
	t.psk = cfg.PresharedKey
	t.tunDev = fwdTUN.(*forwardTUN)

	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wg: device up: %w", err)
	}

	t.logger.Info("wg: forwarding tunnel started",
		"local_addr", cfg.LocalAddress,
		"mtu", mtu,
		"allow", t.allow.String(),
	)

	return nil
}

func (t *forwardingTunnel) Net() *netstack.Net { return nil }

func (t *forwardingTunnel) AddPeer(publicKey string, ip netip.Addr) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return addPeer(t.dev, t.psk, publicKey, ip)
}

func (t *forwardingTunnel) RemovePeer(publicKey string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return removePeer(t.dev, publicKey)
}

func (t *forwardingTunnel) Rehandshake(publicKey string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return rehandshake(t.dev, publicKey)
}

func (t *forwardingTunnel) PeerStatus(publicKey string) (PeerStatus, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return peerStatus(t.dev, publicKey)
}

func (t *forwardingTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
		t.logger.Info("wg: forwarding tunnel closed")
	}
	return nil
}

// buildIPC constructs the WireGuard IPC configuration string: the private
// key and, when cfg names one, the peer. Returns an error if a key cannot be
// decoded.
func buildIPC(cfg TunnelConfig) (string, error) {
	privHex, err := hexKey(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("wg: private key: %w", err)
	}
	ipc := fmt.Sprintf("private_key=%s\n", privHex)
	if cfg.PeerPublicKey == "" {
		return ipc, nil
	}
	peer, err := peerIPC(cfg.PeerPublicKey, cfg.PresharedKey, cfg.AllowedIPs)
	if err != nil {
		return "", err
	}
	return ipc + peer, nil
}

// peerIPC is the IPC section for one peer. Its endpoint is its public key:
// RelayBind tags the peer's packets with it, and the relay routes by it.
func peerIPC(publicKey, presharedKey string, allowed []netip.Prefix) (string, error) {
	peerHex, err := hexKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("wg: peer public key: %w", err)
	}
	var ipc strings.Builder
	fmt.Fprintf(&ipc, "public_key=%s\n", peerHex)
	if presharedKey != "" {
		pskHex, err := hexKey(presharedKey)
		if err != nil {
			return "", fmt.Errorf("wg: preshared key: %w", err)
		}
		fmt.Fprintf(&ipc, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&ipc, "endpoint=%s\n", publicKey)
	ipc.WriteString("replace_allowed_ips=true\n")
	for _, prefix := range allowed {
		fmt.Fprintf(&ipc, "allowed_ip=%s\n", prefix.String())
	}
	return ipc.String(), nil
}

// addPeer adds a peer whose only AllowedIP is ip.
func addPeer(dev *device.Device, psk, publicKey string, ip netip.Addr) error {
	if dev == nil {
		return ErrTunnelClosed
	}
	if !ip.IsValid() {
		return fmt.Errorf("wg: add peer: invalid address %v", ip)
	}
	ipc, err := peerIPC(publicKey, psk, []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())})
	if err != nil {
		return err
	}
	if err := dev.IpcSet(ipc); err != nil {
		return fmt.Errorf("wg: add peer: %w", err)
	}
	return nil
}

func removePeer(dev *device.Device, publicKey string) error {
	if dev == nil {
		return ErrTunnelClosed
	}
	peerHex, err := hexKey(publicKey)
	if err != nil {
		return fmt.Errorf("wg: peer public key: %w", err)
	}
	if err := dev.IpcSet("public_key=" + peerHex + "\nremove=true\n"); err != nil {
		return fmt.Errorf("wg: remove peer: %w", err)
	}
	return nil
}

func rehandshake(dev *device.Device, publicKey string) error {
	if dev == nil {
		return ErrTunnelClosed
	}
	peerHex, err := hexKey(publicKey)
	if err != nil {
		return fmt.Errorf("wg: peer public key: %w", err)
	}
	var pk device.NoisePublicKey
	if err := pk.FromHex(peerHex); err != nil {
		return fmt.Errorf("wg: peer public key: %w", err)
	}
	peer := dev.LookupPeer(pk)
	if peer == nil {
		return fmt.Errorf("wg: rehandshake: no peer %s", publicKey)
	}
	peer.ExpireCurrentKeypairs()
	return peer.SendHandshakeInitiation(false)
}
