// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nfltr/quic-go"
)

// symmetricQAD answers QAD as qadServer does, but answers lie to the source
// whose port is victim's: the observed address of an agent behind an
// endpoint-dependent (symmetric) NAT, whose mapping toward the relay is
// not the one toward its peer.
func symmetricQAD(t *testing.T, victim *net.UDPAddr, lie string) string {
	t.Helper()
	o := newTestOrg(t)
	cert := o.machine(t, "relay", nil, time.Hour, false)
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{QADALPN}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			q, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				s, err := q.OpenUniStream()
				if err == nil {
					answer := q.RemoteAddr().String()
					if q.RemoteAddr().(*net.UDPAddr).Port == victim.Port {
						answer = lie
					}
					_, _ = io.WriteString(s, answer)
					_ = s.Close()
				}
				<-q.Context().Done()
			}()
		}
	}()
	return ln.Addr().String()
}

// blackhole is a UDP address that takes datagrams and never answers.
func blackhole(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

// TestDirectSymmetricAgentGoesDirectPeerReflexively: the agent's offer
// names only an address that never answers (its relay's view under an
// endpoint-dependent NAT); its tagged probe reaches the client from where
// it does answer, and the client dials that address: direct
// (docs/decisions/nat-symmetric-lan-2026-11-16.md, DirectPunch.tla
// W_PrflxWon).
func TestDirectSymmetricAgentGoesDirectPeerReflexively(t *testing.T) {
	r := newDirectRig(t, DirectPublic) // no host candidates: the reflexive one only
	agentAddr := r.l.targets.services.direct.ep.pc.LocalAddr().(*net.UDPAddr)
	r.l.targets.qad.Store(&qadTarget{addr: symmetricQAD(t, agentAddr, blackhole(t)), tls: &tls.Config{InsecureSkipVerify: true}}) // #nosec G402 -- a test's relay
	_, tc, events := r.session(t)
	echo(t, tc, 1<<20, func() {
		e := waitPath(t, events, PathDirect)
		if !e.Peer.Addr().IsLoopback() || e.Peer.Port() != uint16(agentAddr.Port) { // #nosec G115 -- a UDP port
			t.Fatalf("direct to %v, want the agent's probe source %v", e.Peer, agentAddr)
		}
	})
}

// TestDirectProbeRoutesOnlyItsTag: a probe reaches the punch whose
// exchange made its tag; one with another tag, an untagged one and a
// short one reach none (DirectPunch.tla OnlyTagged).
func TestDirectProbeRoutesOnlyItsTag(t *testing.T) {
	e, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck
	from, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	defer from.Close() //nolint:errcheck
	to := netip.MustParseAddrPort("127.0.0.1:" + portOf(e.pc.LocalAddr()))
	tag := make([]byte, probeLen-1)
	tag[0] = 1
	ch, stop := e.listen(tag)
	defer stop()
	other := make([]byte, probeLen-1)
	for _, b := range [][]byte{nil, other, tag[:4]} {
		if err := from.probe([]netip.AddrPort{to}, b); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case a := <-ch:
		t.Fatalf("a probe without the tag was routed: %v", a)
	case <-time.After(300 * time.Millisecond):
	}
	if err := from.probe([]netip.AddrPort{to}, tag); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-ch:
		if a.Port() != from.pc.LocalAddr().(*net.UDPAddr).AddrPort().Port() {
			t.Fatalf("source %v, want the prober's port", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the tagged probe was not routed")
	}
}

func portOf(a net.Addr) string {
	_, p, _ := net.SplitHostPort(a.String())
	return p
}
