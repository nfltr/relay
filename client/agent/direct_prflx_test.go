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
)

// symmetricQAD answers QAD as qadServer does, but answers lie to the source
// whose port is victim's: the observed address of an agent behind an
// endpoint-dependent (symmetric) NAT, whose mapping toward the relay is
// not the one toward its peer. victim nil: it lies to every source.
func symmetricQAD(t *testing.T, victim *net.UDPAddr, lie string) string {
	t.Helper()
	o := newTestOrg(t)
	cert := o.machine(t, "relay", nil, time.Hour, false)
	ln := qadListen(t, cert)
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
					if victim == nil || q.RemoteAddr().(*net.UDPAddr).Port == victim.Port {
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
	r := newDirectRig(t, directReflexive) // no host candidates: the reflexive one only
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
// short one reach none (DirectPunch.tla OnlyTagged). quic-go drops a
// non-QUIC packet that arrives before the endpoint's first
// ReadNonQUICPacket, so another socket first probes a tag of its own
// until it is routed (the endpoint reads); then it sends the wrong
// probes ahead of the tagged prober's, and the next address routed to
// the tag must be the tagged prober's (mutant prflx-any-tag routes the
// other socket's first; no quiet wait).
func TestDirectProbeRoutesOnlyItsTag(t *testing.T) {
	newEndpoint := func() *DirectEndpoint {
		e, err := NewDirectEndpoint()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Close() })
		return e
	}
	e, from, wrong := newEndpoint(), newEndpoint(), newEndpoint()
	to := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:" + portOf(e.pc.LocalAddr()))}
	tag, readyTag := make([]byte, probeLen-1), make([]byte, probeLen-1)
	tag[0], readyTag[0] = 1, 2
	ch, stop := e.listen(tag)
	defer stop()
	ready, stopReady := e.listen(readyTag)
	retry := time.NewTicker(20 * time.Millisecond)
	defer retry.Stop()
	deadline := time.After(5 * time.Second)
	for got := false; !got; {
		if err := wrong.probe(to, readyTag); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ready:
			got = true
		case <-retry.C:
		case <-deadline:
			t.Fatal("the endpoint routed no probe: not reading")
		}
	}
	stopReady() // the retries' late copies now have no punch
	for _, b := range [][]byte{nil, make([]byte, probeLen-1), tag[:4]} {
		if err := wrong.probe(to, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := from.probe(to, tag); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-ch:
		if want := from.pc.LocalAddr().(*net.UDPAddr).AddrPort().Port(); a.Port() != want {
			t.Fatalf("routed %v, want the tagged prober's port %d: a probe without the tag was routed", a, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the tagged probe was not routed")
	}
}

func portOf(a net.Addr) string {
	_, p, _ := net.SplitHostPort(a.String())
	return p
}
