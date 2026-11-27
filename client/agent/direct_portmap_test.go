// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// No test asks the machine's real gateway: a NAT-PMP router on the test
// machine's LAN would map its ports. A test that wants one serves it.
func init() {
	discoverGateway = func() (net.IP, error) { return nil, errors.New("tests: no LAN gateway") }
	ssdpGroup = netip.AddrPort{} // no multicast M-SEARCH from a test
}

// quietSSDP is a UDP port that reads and never answers: a test gateway's
// SSDP port when it has no IGD (never the machine's own 1900).
func quietSSDP(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// natpmpGateway is a NAT-PMP server (RFC 6886) on 127.0.0.1 at its own
// port (never the fixed 5351, which another test process may hold) that maps
// only the UDP port mapsPort, through a forwarder that stands for the
// router's NAT: datagrams to the mapped port reach mapsPort from the
// forwarder's inside socket, and its answers go back from the mapped port.
type natpmpGateway struct {
	port int          // the NAT-PMP server's port
	ext  *net.UDPAddr // the mapped address
	mu   sync.Mutex
	asks []uint32 // each NAT-PMP map request's lifetime
	pcp  bool     // answers PCP (else a PCP request gets NAT-PMP's Unsupported Version)
	pcps []pcpAsk // each PCP MAP request
}

type pcpAsk struct {
	life  uint32
	nonce [12]byte
}

func serveNATPMP(t *testing.T, mapsPort int) *natpmpGateway { return serveGateway(t, mapsPort, false) }

// servePCP is serveNATPMP's gateway answering PCP too (RFC 6887).
func servePCP(t *testing.T, mapsPort int) *natpmpGateway { return serveGateway(t, mapsPort, true) }

func (g *natpmpGateway) setPCP(on bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pcp = on
}

func (g *natpmpGateway) pcpAsks() []pcpAsk {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]pcpAsk(nil), g.pcps...)
}

// answerPCP is the gateway's answer to the PCP request b (nil: none).
func (g *natpmpGateway) answerPCP(b []byte, mapsPort int) []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(b) != pcpLen || b[1] != pcpOpMap {
		return nil
	}
	life, in := binary.BigEndian.Uint32(b[4:]), binary.BigEndian.Uint16(b[40:])
	g.pcps = append(g.pcps, pcpAsk{life: life, nonce: [12]byte(b[24:36])})
	if !g.pcp { // RFC 6886 3.5: Unsupported Version
		return []byte{0, 0x80 | b[1], 0, 1, 0, 0, 0, 1}
	}
	out := append([]byte(nil), b...)
	out[1], out[2], out[3] = 0x80|pcpOpMap, 0, 0
	copy(out[8:24], make([]byte, 16)) // epoch 0, reserved
	out[11] = 1
	ext := uint16(g.ext.Port) // #nosec G115 -- a UDP port
	if int(in) != mapsPort {
		out[3], ext = 2, 0 // NOT_AUTHORIZED
	}
	binary.BigEndian.PutUint16(out[42:], ext)
	a := netip.AddrFrom16(netip.AddrFrom4([4]byte{127, 0, 0, 1}).As16()).As16()
	copy(out[44:], a[:])
	return out
}

func serveGateway(t *testing.T, mapsPort int, pcp bool) *natpmpGateway {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	outside, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	inside, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outside.Close(); _ = inside.Close() })
	g := &natpmpGateway{port: pc.LocalAddr().(*net.UDPAddr).Port, ext: outside.LocalAddr().(*net.UDPAddr), pcp: pcp}
	internal := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mapsPort}
	var peer sync.Map // the last peer that sent to the mapped port
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := outside.ReadFromUDP(b)
			if err != nil {
				return
			}
			peer.Store(0, from)
			_, _ = inside.WriteToUDP(b[:n], internal)
		}
	}()
	go func() {
		b := make([]byte, 2048)
		for {
			n, _, err := inside.ReadFromUDP(b)
			if err != nil {
				return
			}
			if to, ok := peer.Load(0); ok {
				_, _ = outside.WriteToUDP(b[:n], to.(*net.UDPAddr))
			}
		}
	}()
	go func() {
		b := make([]byte, 128)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			if n >= 2 && b[0] == pcpVersion {
				if out := g.answerPCP(b[:n], mapsPort); out != nil {
					_, _ = pc.WriteTo(out, from)
				}
				continue
			}
			if n < 2 || b[0] != 0 {
				continue
			}
			out := []byte{0, 128 + b[1], 0, 0, 0, 0, 0, 1}
			switch {
			case b[1] == 0 && n == 2: // the external address
				out = append(out, 127, 0, 0, 1)
			case b[1] == 1 && n == 12: // a UDP mapping
				in, life := binary.BigEndian.Uint16(b[4:]), binary.BigEndian.Uint32(b[8:])
				g.mu.Lock()
				g.asks = append(g.asks, life)
				g.mu.Unlock()
				ext := uint16(g.ext.Port) // #nosec G115 -- a UDP port
				if int(in) != mapsPort {
					out[3], ext = 2, 0 // Not Authorized/Refused
				}
				out = binary.BigEndian.AppendUint16(out, in)
				out = binary.BigEndian.AppendUint16(out, ext)
				out = binary.BigEndian.AppendUint32(out, life)
			default:
				continue
			}
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return g
}

// localGateway: a test endpoint's gateway is 127.0.0.1 (the NAT-PMP
// server a test serves), set on the endpoint, never in discoverGateway.
func localGateway() (net.IP, error) { return net.IPv4(127, 0, 0, 1), nil }

func (g *natpmpGateway) lifetimes() []uint32 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]uint32(nil), g.asks...)
}

// TestDirectMappedAgentGoesDirect: both ends behind endpoint-dependent
// NATs (each one's QAD answer an address that never answers, so neither a
// reflexive candidate nor a probe's source opens the pair); the agent's
// gateway maps its port, its offer carries the mapped address, and the
// client goes direct through it (docs/decisions/portmap-2026-11-16.md).
func TestDirectMappedAgentGoesDirect(t *testing.T) {
	r := newDirectRig(t, directReflexive) // no host candidates
	ep := r.l.targets.services.direct.ep
	ep.gateway, ep.ssdp = localGateway, quietSSDP(t)
	g := serveNATPMP(t, ep.pc.LocalAddr().(*net.UDPAddr).Port)
	ep.natpmp = g.port
	r.l.targets.qad.Store(&qadTarget{addr: symmetricQAD(t, nil, blackhole(t)), tls: &tls.Config{InsecureSkipVerify: true}}) // #nosec G402 -- a test's relay
	_, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() {
		e := waitPath(t, events, PathDirect)
		if e.Peer.Port() != uint16(g.ext.Port) { // #nosec G115 -- a UDP port
			t.Fatalf("direct to %v, want the mapped address %v", e.Peer, g.ext)
		}
	})
}

// TestDirectPortMapLease: the mapping is the socket's own port for
// portMapLifetime, asked again (renewed) at each offer, deleted (lifetime
// 0) on Close; a refusal is asked again too.
func TestDirectPortMapLease(t *testing.T) {
	ep, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	ep.loopback = true
	ep.gateway, ep.ssdp = localGateway, quietSSDP(t)
	g := serveNATPMP(t, ep.pc.LocalAddr().(*net.UDPAddr).Port)
	ep.natpmp = g.port
	for range 2 {
		a, ok := ep.mapped()
		if !ok || a.Port() != uint16(g.ext.Port) { // #nosec G115 -- a UDP port
			t.Fatalf("mapped %v %v, want %v", a, ok, g.ext)
		}
	}
	if err := ep.Close(); err != nil {
		t.Fatal(err)
	}
	if got := g.lifetimes(); len(got) != 3 || got[0] != portMapLifetime || got[1] != portMapLifetime || got[2] != 0 {
		t.Fatalf("map requests' lifetimes %v, want [%d %d 0]", got, portMapLifetime, portMapLifetime)
	}

	other, err := NewDirectEndpoint() // the gateway refuses its port
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close() //nolint:errcheck
	other.gateway, other.natpmp, other.ssdp = localGateway, g.port, quietSSDP(t)
	for range 2 {
		if a, ok := other.mapped(); ok {
			t.Fatalf("refused port mapped to %v", a)
		}
	}
	if got := g.lifetimes(); len(got) != 5 {
		t.Fatalf("%d map requests, want 5 (a refusal asked again)", len(got))
	}
}

// TestDirectPortMapSilentGateway: a gateway that never answers costs one
// ask its bound, then none for portMapRetry.
func TestDirectPortMapSilentGateway(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // reads, never answers
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close() //nolint:errcheck
	ep, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	ep.gateway, ep.natpmp, ep.ssdp = localGateway, pc.LocalAddr().(*net.UDPAddr).Port, pc.LocalAddr().(*net.UDPAddr).Port
	defer ep.Close() //nolint:errcheck
	for i, want := range []time.Duration{silentBound, 0} {
		start := time.Now()
		if a, ok := ep.mapped(); ok {
			t.Fatalf("silent gateway mapped %v", a)
		}
		if d := time.Since(start); (want == 0) != (d < portMapBound/2) {
			t.Fatalf("ask %d took %v, want %v", i, d, want)
		}
	}
}

// TestPortMapNoMapAfterClose: once the endpoint closed, no ask maps its
// port (spec/PortMap.tla NoMapAfterClose): a late gather's ask would leave
// a mapping on the router that nothing deletes until its lease ends.
func TestPortMapNoMapAfterClose(t *testing.T) {
	ep, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	ep.loopback = true
	ep.gateway, ep.ssdp = localGateway, quietSSDP(t)
	g := serveNATPMP(t, ep.pc.LocalAddr().(*net.UDPAddr).Port)
	ep.natpmp = g.port
	if err := ep.Close(); err != nil {
		t.Fatal(err)
	}
	if a, ok := ep.mapped(); ok {
		t.Fatalf("closed endpoint mapped %v", a)
	}
	if got := g.lifetimes(); len(got) != 0 {
		t.Fatalf("map requests after the close: %v", got)
	}
}

// TestDirectPortMapPCP: a PCP gateway maps the socket's own port with
// PCP (no NAT-PMP ask), renewed with the same nonce at each offer and
// deleted (lifetime 0, that nonce) on Close (RFC 6887 11.1, 15).
func TestDirectPortMapPCP(t *testing.T) {
	ep, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	ep.loopback = true
	ep.gateway, ep.ssdp = localGateway, quietSSDP(t)
	g := servePCP(t, ep.pc.LocalAddr().(*net.UDPAddr).Port)
	ep.natpmp = g.port
	for range 2 {
		a, ok := ep.mapped()
		if !ok || a.Port() != uint16(g.ext.Port) || a.Addr() != netip.MustParseAddr("127.0.0.1") { // #nosec G115 -- a UDP port
			t.Fatalf("mapped %v %v, want %v", a, ok, g.ext)
		}
	}
	if err := ep.Close(); err != nil {
		t.Fatal(err)
	}
	got := g.pcpAsks()
	if len(got) != 3 || got[0].life != portMapLifetime || got[1].life != portMapLifetime || got[2].life != 0 {
		t.Fatalf("PCP requests %+v, want lifetimes [%d %d 0]", got, portMapLifetime, portMapLifetime)
	}
	if got[0].nonce != got[1].nonce || got[1].nonce != got[2].nonce || got[0].nonce == [12]byte{} {
		t.Fatalf("nonces %x %x %x, want one, the mapping's", got[0].nonce, got[1].nonce, got[2].nonce)
	}
	if n := len(g.lifetimes()); n != 0 {
		t.Fatalf("%d NAT-PMP requests to a PCP gateway", n)
	}
}

// TestDirectPortMapSwitchDeletesOld: the gateway stops answering PCP (a
// new router); the next offer maps with NAT-PMP and deletes the PCP
// mapping (spec/PortMap.tla OneLive, mutant ask-all).
func TestDirectPortMapSwitchDeletesOld(t *testing.T) {
	ep, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close() //nolint:errcheck
	ep.loopback = true
	ep.gateway, ep.ssdp = localGateway, quietSSDP(t)
	g := servePCP(t, ep.pc.LocalAddr().(*net.UDPAddr).Port)
	ep.natpmp = g.port
	if _, ok := ep.mapped(); !ok {
		t.Fatal("no PCP mapping")
	}
	g.setPCP(false)
	if _, ok := ep.mapped(); !ok {
		t.Fatal("no NAT-PMP mapping")
	}
	got := g.pcpAsks()
	if len(got) != 3 || got[2].life != 0 || got[2].nonce != got[0].nonce {
		t.Fatalf("PCP requests %+v, want the map, the next offer's ask (Unsupported Version) and the delete", got)
	}
	if l := g.lifetimes(); len(l) != 1 || l[0] != portMapLifetime {
		t.Fatalf("NAT-PMP requests %v, want one map", l)
	}
}
