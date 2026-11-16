// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// No test asks the machine's real gateway: a NAT-PMP router on the test
// machine's LAN would map its ports. A test that wants one serves it.
func init() {
	discoverGateway = func() (net.IP, error) { return nil, errors.New("tests: no LAN gateway") }
}

// natpmpGateway is a NAT-PMP server (RFC 6886) on 127.0.0.1:5351 that maps
// only the UDP port mapsPort, through a forwarder that stands for the
// router's NAT: datagrams to the mapped port reach mapsPort from the
// forwarder's inside socket, and its answers go back from the mapped port.
type natpmpGateway struct {
	ext  *net.UDPAddr // the mapped address
	mu   sync.Mutex
	asks []uint32 // each map request's lifetime
}

func serveNATPMP(t *testing.T, mapsPort int) *natpmpGateway {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:5351")
	if err != nil {
		t.Fatalf("NAT-PMP port taken: %v", err)
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
	g := &natpmpGateway{ext: outside.LocalAddr().(*net.UDPAddr)}
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
		b := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
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
	discoverGateway = func() (net.IP, error) { return net.IPv4(127, 0, 0, 1), nil }
	t.Cleanup(func() { discoverGateway = func() (net.IP, error) { return nil, errors.New("tests: no LAN gateway") } })
	return g
}

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
	g := serveNATPMP(t, ep.pc.LocalAddr().(*net.UDPAddr).Port)
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
	g := serveNATPMP(t, ep.pc.LocalAddr().(*net.UDPAddr).Port)
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
	pc, err := net.ListenPacket("udp", "127.0.0.1:5351") // reads, never answers
	if err != nil {
		t.Fatalf("NAT-PMP port taken: %v", err)
	}
	defer pc.Close() //nolint:errcheck
	discoverGateway = func() (net.IP, error) { return net.IPv4(127, 0, 0, 1), nil }
	defer func() { discoverGateway = func() (net.IP, error) { return nil, errors.New("tests: no LAN gateway") } }()
	ep, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close() //nolint:errcheck
	for i, want := range []time.Duration{portMapBound, 0} {
		start := time.Now()
		if a, ok := ep.mapped(); ok {
			t.Fatalf("silent gateway mapped %v", a)
		}
		if d := time.Since(start); (want == 0) != (d < portMapBound/2) {
			t.Fatalf("ask %d took %v, want %v", i, d, want)
		}
	}
}
