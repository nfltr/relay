// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// Port mapping (nfltr docs/decisions/portmap-2026-11-16.md,
// hardnat-2026-11-25.md; spec/PortMap.tla): with a direct mode on, the
// endpoint asks the LAN's default gateway to map its UDP port, PCP (RFC
// 6887, direct_pcp.go) first, then NAT-PMP (RFC 6886), then UPnP-IGD
// (direct_upnp.go), and offers the mapped address as one more candidate. Under an endpoint-dependent (symmetric) NAT whose router
// maps, that address answers every peer, so the pair goes direct where the
// reflexive candidate cannot. The punch's certificate and token checks
// authenticate whoever comes through it, as for every candidate.

import (
	"cmp"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jackpal/gateway"
)

const (
	// portMapLifetime is the mapping's requested lease (RFC 6886 3.3:
	// 7200 s recommended). Every offer renews it.
	portMapLifetime = 7200
	// portMapBound bounds one NAT-PMP ask (two tries, 250 ms each): a
	// gateway on the LAN answers, or refuses (ICMP), in milliseconds.
	portMapBound = 500 * time.Millisecond
	// silentBound: a gateway silent to every protocol cost this ask.
	silentBound = pcpBound + portMapBound + upnpBound
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

var (
	// errNoAnswer: a gateway's silence within one protocol's bound.
	errNoAnswer = errors.New("the gateway did not answer")
	// errSilent: the gateway was silent to every protocol.
	errSilent = errors.New("the gateway answered no port mapping protocol")
)

// The protocols a mapping is made with (spec/PortMap.tla Order).
const (
	protoPCP    = "pcp"
	protoNATPMP = "natpmp"
)

// portMap is an endpoint's mapping: the gateway that made it, the
// protocol, the mapped address (invalid: none), PCP's nonce and UPnP's
// service for it, a
// silent gateway with until when it is believed silent, and whether the
// endpoint closed (no ask after it: spec/PortMap.tla NoMapAfterClose).
type portMap struct {
	mu     sync.Mutex
	gw     net.IP
	proto  string
	ext    netip.AddrPort
	nonce  [12]byte
	upnp   upnpCtl      // the IGD service that mapped (proto upnp)
	tr     portMapTrace // spec/TracePortMap.tla's steps (-tags relaytrace)
	silent net.IP
	until  time.Time
	closed bool
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
	if m.closed || gw.Equal(m.silent) && time.Now().Before(m.until) {
		return netip.AddrPort{}, false
	}
	if !m.ext.IsValid() || !gw.Equal(m.gw) {
		if _, err := rand.Read(m.nonce[:]); err != nil { // a new mapping's nonce (RFC 6887 11.1); a renewal keeps it
			return netip.AddrPort{}, false
		}
	}
	ext, proto, ctl, err := e.askAny(m, gw, portMapLifetime)
	if err != nil {
		if errors.Is(err, errSilent) {
			m.silent, m.until = gw, time.Now().Add(portMapRetry)
		}
		slog.Debug("direct path: no port mapping", "gateway", gw, "error", err)
		return netip.AddrPort{}, false
	}
	if m.ext.IsValid() && (m.proto != proto || !gw.Equal(m.gw)) {
		e.del(m) // one live mapping (spec/PortMap.tla OneLive): the old one's delete, best effort
	}
	m.gw, m.proto, m.ext, m.upnp = gw, proto, ext, ctl
	return ext, true
}

// askAny maps (life > 0) this endpoint's port at gw: PCP, then NAT-PMP
// when the gateway answered PCP with version 0 or not at all (RFC 6887
// appendix A), then UPnP-IGD. A mapping held at gw is renewed with its
// own protocol first (no discovery, no other protocol's wait); if that
// fails, in that order (spec/PortMap.tla Round, NotMapped). errSilent:
// every protocol was silent. The UPnP service is the one that mapped.
// m.mu held.
func (e *DirectEndpoint) askAny(m *portMap, gw net.IP, life uint32) (netip.AddrPort, string, upnpCtl, error) {
	ip, _ := netip.AddrFromSlice(gw.To4())
	ask := func(p string, ctl upnpCtl) (netip.AddrPort, upnpCtl, error) {
		var ext netip.AddrPort
		var err error
		switch p {
		case protoPCP:
			ext, err = e.askPCP(e.gatewayPort(gw), m.nonce, life)
		case protoNATPMP:
			ext, err = e.askMap(gw, life)
		default:
			ext, ctl, err = e.askUPnP(ip, ctl, life)
		}
		if err != nil {
			m.tr.line("NotMapped", p, false, life)
		} else {
			m.tr.line("Mapped", p, m.ext.IsValid() && (m.proto != p || !gw.Equal(m.gw)), life) // mapped deletes the old one
		}
		return ext, ctl, err
	}
	held := ""
	if m.ext.IsValid() && gw.Equal(m.gw) && m.proto != protoPCP {
		held = m.proto
	}
	m.tr.line("Round", cmp.Or(held, protoPCP), false, life)
	if held != "" {
		if ext, ctl, err := ask(held, m.upnp); err == nil {
			return ext, held, ctl, nil
		}
	}
	ext, _, err := ask(protoPCP, upnpCtl{})
	if err == nil {
		return ext, protoPCP, upnpCtl{}, nil
	}
	errs := []error{err}
	if errors.Is(err, errPCPVersion) || errors.Is(err, errNoAnswer) { // else the gateway speaks PCP and said no
		if ext, _, err = ask(protoNATPMP, upnpCtl{}); err == nil {
			return ext, protoNATPMP, upnpCtl{}, nil
		}
		errs = append(errs, err)
	}
	ext, ctl, err := ask(protoUPnP, upnpCtl{})
	if err == nil {
		return ext, protoUPnP, ctl, nil
	}
	errs = append(errs, err)
	for _, err := range errs {
		if !errors.Is(err, errNoAnswer) {
			return netip.AddrPort{}, "", upnpCtl{}, errors.Join(errs...)
		}
	}
	return netip.AddrPort{}, "", upnpCtl{}, errSilent
}

// gatewayPort is gw's PCP and NAT-PMP port (5351, or a test's).
func (e *DirectEndpoint) gatewayPort(gw net.IP) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(gw.To4())
	port := e.natpmp
	if port == 0 {
		port = natpmpPort
	}
	return netip.AddrPortFrom(ip, uint16(port)) // #nosec G115 -- a UDP port
}

// del deletes m's mapping with the protocol that made it (lifetime 0:
// RFC 6886 3.4, RFC 6887 15), one bounded ask; an unanswered delete
// leaves it to its lease. m.mu held.
func (e *DirectEndpoint) del(m *portMap) {
	switch m.proto {
	case protoPCP:
		_, _ = e.askPCP(e.gatewayPort(m.gw), m.nonce, 0)
	case protoNATPMP:
		_, _ = e.askMap(m.gw, 0)
	case protoUPnP:
		m.upnp.unmapUPnP(int(m.ext.Port()))
	}
	m.ext = netip.AddrPort{}
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
	at := e.gatewayPort(gw)
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
// bytes, resending within portMapBound (udpAsk). The connected socket
// hears only the gateway.
func natpmpAsk(at netip.AddrPort, req []byte, size int) ([]byte, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(at))
	if err != nil {
		return nil, err
	}
	defer c.Close() //nolint:errcheck
	b, err := udpAsk(c, req, portMapBound)
	n := len(b)
	switch {
	case err != nil:
		return nil, fmt.Errorf("natpmp: %w", err)
	case n < 4 || b[0] != 0 || b[1] != req[1]|0x80:
		return nil, fmt.Errorf("natpmp: unexpected answer % x", b)
	case binary.BigEndian.Uint16(b[2:4]) != 0:
		return nil, fmt.Errorf("natpmp: result code %d", binary.BigEndian.Uint16(b[2:4]))
	case n != size:
		return nil, fmt.Errorf("natpmp: answer of %d bytes, want %d", n, size)
	}
	return b, nil
}

// unmap deletes a held mapping (del), once, bounded;
// an unanswered delete leaves it to expire with its lease. An ask in
// flight holds the lock, so its mapping is deleted here; none starts after.
func (e *DirectEndpoint) unmap() {
	m := &e.pm
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.tr.line("Close", m.proto, m.ext.IsValid(), 0)
	}
	m.closed = true
	if m.ext.IsValid() {
		e.del(m)
	}
	m.tr.end()
}
