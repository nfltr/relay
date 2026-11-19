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
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/jackpal/gateway"
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
	// natpmpPort is the gateway's NAT-PMP port (RFC 6886 3.1). A test's
	// fake gateway binds port 0 and sets the endpoint's natpmp instead.
	natpmpPort = 5351
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
func (e *DirectEndpoint) askMap(gw net.IP, life uint32) (netip.AddrPort, error) {
	ua, ok := e.pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, net.UnknownNetworkError("udp")
	}
	ip, _ := netip.AddrFromSlice(gw.To4())
	port := e.natpmp
	if port == 0 {
		port = natpmpPort
	}
	at := netip.AddrPortFrom(ip, uint16(port))                // #nosec G115 -- a UDP port
	req := []byte{0, 1, 0, 0}                                 // RFC 6886 3.3: version 0, map UDP, reserved
	req = binary.BigEndian.AppendUint16(req, uint16(ua.Port)) // #nosec G115 -- a UDP port
	req = binary.BigEndian.AppendUint16(req, uint16(ua.Port)) // #nosec G115 -- a UDP port
	req = binary.BigEndian.AppendUint32(req, life)
	r, err := natpmpAsk(at, req, 16)
	if err != nil || life == 0 {
		return netip.AddrPort{}, err
	}
	x, err := natpmpAsk(at, []byte{0, 0}, 12) // RFC 6886 3.2: the external address
	if err != nil {
		return netip.AddrPort{}, err
	}
	return e.candidate(netip.AddrPortFrom(netip.AddrFrom4([4]byte(x[8:12])), binary.BigEndian.Uint16(r[10:12])).String())
}

// natpmpAsk sends req to the gateway at and returns its answer, size
// bytes, resending (RFC 6886 3.1: 250 ms, doubling) within portMapBound.
// The connected socket hears only the gateway.
func natpmpAsk(at netip.AddrPort, req []byte, size int) ([]byte, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(at))
	if err != nil {
		return nil, err
	}
	defer c.Close() //nolint:errcheck
	end := time.Now().Add(portMapBound)
	b := make([]byte, 16)
	for wait := 250 * time.Millisecond; time.Now().Before(end); wait *= 2 {
		d := time.Now().Add(wait)
		if d.After(end) {
			d = end
		}
		if err := c.SetDeadline(d); err != nil {
			return nil, err
		}
		if _, err := c.Write(req); err != nil {
			return nil, err
		}
		n, err := c.Read(b)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return nil, err
		}
		switch {
		case n < 4 || b[0] != 0 || b[1] != req[1]|0x80:
			return nil, fmt.Errorf("natpmp: unexpected answer % x", b[:n])
		case binary.BigEndian.Uint16(b[2:4]) != 0:
			return nil, fmt.Errorf("natpmp: result code %d", binary.BigEndian.Uint16(b[2:4]))
		case n != size:
			return nil, fmt.Errorf("natpmp: answer of %d bytes, want %d", n, size)
		}
		return b[:n], nil
	}
	return nil, errors.New("natpmp: the gateway did not answer")
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
