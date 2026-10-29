// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package wg

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// KernelTunnelSupported reports whether NewKernelTunnel works on this OS.
const KernelTunnelSupported = true

// NewKernelTunnel creates a WireGuard tunnel on a kernel TUN interface, so
// every program on the machine reaches cfg.AllowedIPs through it (`nfltr wg
// connect`). It needs CAP_NET_ADMIN and /dev/net/tun, and configures the
// interface with the `ip` command.
func NewKernelTunnel(logger *slog.Logger) Tunnel {
	if logger == nil {
		logger = slog.Default()
	}
	return &kernelTunnel{logger: logger}
}

type kernelTunnel struct {
	logger *slog.Logger
	mu     sync.Mutex
	dev    *device.Device
	psk    string
	closed bool
}

func (t *kernelTunnel) Start(_ context.Context, cfg TunnelConfig, bind *RelayBind) error {
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
	tunDev, err := tun.CreateTUN("nfltr%d", mtu)
	if err != nil {
		return fmt.Errorf("wg: create kernel TUN (needs CAP_NET_ADMIN and /dev/net/tun; without them use `nfltr wg socks5`): %w", err)
	}
	name, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return fmt.Errorf("wg: kernel TUN name: %w", err)
	}
	// The device brings itself up on the TUN's EventUp, which the link-up
	// below triggers (the wireguard-go convention).
	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelSilent, "wg: "))
	ipcConf, err := buildIPC(cfg)
	if err != nil {
		dev.Close()
		return err
	}
	if err := dev.IpcSet(ipcConf); err != nil {
		dev.Close()
		return fmt.Errorf("wg: ipc set: %w", err)
	}
	steps := [][]string{
		{"addr", "add", cfg.LocalAddress.String() + "/" + fmt.Sprint(cfg.LocalAddress.BitLen()), "dev", name},
		{"link", "set", "dev", name, "up"},
	}
	for _, prefix := range cfg.AllowedIPs {
		steps = append(steps, []string{"route", "add", prefix.Masked().String(), "dev", name})
	}
	for _, args := range steps {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			dev.Close()
			return fmt.Errorf("wg: ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	t.dev = dev
	t.psk = cfg.PresharedKey
	t.logger.Info("wg: kernel tunnel started", "interface", name, "local_addr", cfg.LocalAddress, "mtu", mtu)
	return nil
}

func (t *kernelTunnel) Net() *netstack.Net { return nil }

// AddPeer adds a peer; it adds no route (routes come from cfg.AllowedIPs).
func (t *kernelTunnel) AddPeer(publicKey string, ip netip.Addr) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return addPeer(t.dev, t.psk, publicKey, ip)
}

func (t *kernelTunnel) RemovePeer(publicKey string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return removePeer(t.dev, publicKey)
}

func (t *kernelTunnel) Rehandshake(publicKey string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return rehandshake(t.dev, publicKey)
}

func (t *kernelTunnel) PeerStatus(publicKey string) (PeerStatus, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return peerStatus(t.dev, publicKey)
}

func (t *kernelTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.dev != nil {
		t.dev.Close() // closing the TUN removes the interface and its routes
		t.dev = nil
	}
	return nil
}
