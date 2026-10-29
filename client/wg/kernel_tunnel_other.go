// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package wg

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// KernelTunnelSupported reports whether NewKernelTunnel works on this OS.
const KernelTunnelSupported = false

// NewKernelTunnel reports that kernel TUN tunnels are Linux-only here; use
// `nfltr wg socks5` on other systems.
func NewKernelTunnel(*slog.Logger) Tunnel { return kernelTunnelUnsupported{} }

type kernelTunnelUnsupported struct{}

// Start fails: there is no kernel TUN here. allow:wrapper — Tunnel method.
func (kernelTunnelUnsupported) Start(context.Context, TunnelConfig, *RelayBind) error {
	return errors.New("wg: `nfltr wg connect` needs a Linux kernel TUN; on this system use `nfltr wg socks5`")
}

func (kernelTunnelUnsupported) Net() *netstack.Net { return nil }

func (kernelTunnelUnsupported) AddPeer(string, netip.Addr) error { return ErrTunnelClosed }

func (kernelTunnelUnsupported) RemovePeer(string) error { return ErrTunnelClosed }

func (kernelTunnelUnsupported) Rehandshake(string) error { return ErrTunnelClosed }
func (kernelTunnelUnsupported) PeerStatus(string) (PeerStatus, error) {
	return PeerStatus{}, ErrTunnelClosed
}

func (kernelTunnelUnsupported) Close() error { return nil }
