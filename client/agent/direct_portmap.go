// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// Port mapping (nfltr docs/decisions/portmap-2026-11-16.md): with a direct
// mode on, the endpoint asks the LAN's default gateway for a NAT-PMP
// mapping (RFC 6886) of its UDP port and offers the mapped address as one
// more candidate. Under an endpoint-dependent (symmetric) NAT whose router
// maps, that address answers every peer, so the pair goes direct where the
// reflexive candidate cannot. The punch's certificate and token checks
// authenticate whoever comes through it, as for every candidate.

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jackpal/gateway"
	natpmp "github.com/jackpal/go-nat-pmp"
)

const (
	// portMapLifetime is the mapping's requested lease (RFC 6886 3.3:
	// 7200 s recommended). Every offer renews it.
	portMapLifetime = 7200
	// portMapBound bounds one ask (two NAT-PMP tries, 250 ms each): a
	// gateway on the LAN answers, or refuses (ICMP), in milliseconds.
	portMapBound = 500 * time.Millisecond
	// portMapRetry is how long a gateway that never answered is believed
	// silent: each control exchange would otherwise wait portMapBound.
	portMapRetry = 10 * time.Minute
)

// discoverGateway is the LAN's default IPv4 gateway (the routing table).
// Only a test package's init replaces it: a test that serves a gateway sets
// its endpoint's gateway, since a write here races with an earlier test's
// endpoint still asking (relay stress-cirelay af430bafa063, -race).
var discoverGateway = gateway.DiscoverGateway

// portMap is an endpoint's mapping: the gateway that made it and the
// mapped address (invalid: none), and a silent gateway with until when it
// is believed silent.
type portMap struct {
	mu     sync.Mutex
	gw     net.IP
	ext    netip.AddrPort
	silent net.IP
	until  time.Time
}

// mapped asks the gateway to map (or renew, the same request) this
// endpoint's UDP port: the mapped address. Asked at each offer, so a
// router that restarted or a network that changed is asked again; only a
// gateway that never answered is left alone for portMapRetry. ok false:
// no gateway, no answer, or a refusal.
func (e *DirectEndpoint) mapped() (netip.AddrPort, bool) {
	discover := discoverGateway
	if e.gateway != nil {
		discover = e.gateway
	}
	gw, err := discover()
	if err != nil || gw.To4() == nil {
		return netip.AddrPort{}, false
	}
	m := &e.pm
	m.mu.Lock()
	defer m.mu.Unlock()
	if gw.Equal(m.silent) && time.Now().Before(m.until) {
		return netip.AddrPort{}, false
	}
	start := time.Now()
	ext, err := e.askMap(gw, portMapLifetime)
	if err != nil {
		if time.Since(start) >= portMapBound {
			m.silent, m.until = gw, time.Now().Add(portMapRetry)
		}
		slog.Debug("direct path: no port mapping", "gateway", gw, "error", err)
		return netip.AddrPort{}, false
	}
	m.gw, m.ext = gw, ext
	return ext, true
}

// mapping asks for the mapped address beside other work (QAD): its one
// value is the address, or the zero one.
func (e *DirectEndpoint) mapping() <-chan netip.AddrPort {
	c := make(chan netip.AddrPort, 1)
	go func() { a, _ := e.mapped(); c <- a }()
	return c
}

// askMap asks gw to map this endpoint's UDP port for life seconds (0
// deletes it): the mapped port, then the gateway's external address.
func (e *DirectEndpoint) askMap(gw net.IP, life int) (netip.AddrPort, error) {
	ua, ok := e.pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, net.UnknownNetworkError("udp")
	}
	c := natpmp.NewClientWithTimeout(gw, portMapBound)
	r, err := c.AddPortMapping("udp", ua.Port, ua.Port, life)
	if err != nil || life == 0 {
		return netip.AddrPort{}, err
	}
	x, err := c.GetExternalAddress()
	if err != nil {
		return netip.AddrPort{}, err
	}
	return e.candidate(netip.AddrPortFrom(netip.AddrFrom4(x.ExternalIPAddress), r.MappedExternalPort).String())
}

// unmap deletes a held mapping (RFC 6886 3.4: lifetime 0), once, bounded;
// an unanswered delete leaves it to expire with its lease.
func (e *DirectEndpoint) unmap() {
	m := &e.pm
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ext.IsValid() {
		_, _ = e.askMap(m.gw, 0)
	}
	m.ext = netip.AddrPort{}
}
