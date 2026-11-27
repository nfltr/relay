// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
)

// TestDirectIPv6HostCandidates: each end offers only an IPv6 host
// candidate beside a reflexive one that never answers (an IPv4 NAT that
// opens nothing): the dual-stack socket goes direct over IPv6, where no
// NAT stands (nfltr docs/decisions/hardnat-2026-11-25.md, technique 2).
func TestDirectIPv6HostCandidates(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback on this machine: %v", err)
	} else {
		_ = c.Close()
	}
	r := newDirectRig(t, DirectOn)
	v6 := func(ep *DirectEndpoint) []netip.AddrPort {
		return []netip.AddrPort{netip.AddrPortFrom(netip.IPv6Loopback(), uint16(ep.pc.LocalAddr().(*net.UDPAddr).Port))} // #nosec G115 -- a UDP port
	}
	agent := r.l.targets.services.direct.ep
	agent.hosts, r.d.ep.hosts = v6(agent), v6(r.d.ep)
	r.l.targets.qad.Store(&qadTarget{addr: symmetricQAD(t, nil, blackhole(t)), tls: &tls.Config{InsecureSkipVerify: true}}) // #nosec G402 -- a test's relay
	_, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() {
		if e := waitPath(t, events, PathDirect); !e.Peer.Addr().Is6() {
			t.Fatalf("direct to %v, want the IPv6 candidate", e.Peer)
		}
	})
}
