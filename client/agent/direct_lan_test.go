// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
)

// gatedConn reads nothing until gate (or stop) closes: a peer whose
// handshake starts only once an event (the punch took another candidate's
// result: TestDirectPunchPrefersLAN), not a delay: a loaded machine keeps
// the order.
type gatedConn struct {
	net.PacketConn
	gate, stop <-chan struct{}
}

func (c gatedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-c.gate:
	case <-c.stop:
	}
	return c.PacketConn.ReadFrom(b)
}

// quicPeer is a QUIC server on loopback answering quiclink's ALPN that
// reads once gate closes.
func quicPeer(t *testing.T, gate <-chan struct{}) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := newTestOrg(t).machine(t, "peer", nil, time.Hour, false)
	stop := make(chan struct{})
	tr := &quic.Transport{Conn: gatedConn{pc, gate, stop}}
	// The transport's Close ends every connection of it, a listener's
	// only the handshakes (a peer whose dial was cancelled sends no close).
	t.Cleanup(func() { close(stop); _ = tr.Close(); _ = pc.Close() })
	ln, err := tr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quiclink.ALPNChain, quiclink.ALPN}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			q, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-q.Context().Done() }()
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// TestDirectPunchPrefersLAN: a non-LAN candidate answers first, a LAN one
// only after it (within the grace): the punch keeps the LAN connection
// (DirectPunch.tla PreferLan, mutant first-wins). The LAN peer reads
// nothing until the punch's loop took the non-LAN connection (e.took), so
// the loop receives the two in that order however the dials' goroutines
// are scheduled: gated on the non-LAN peer's Accept only, the LAN result
// could reach the loop first and the Go mutant lan-first-wins passed (box
// log 20261120T175411Z-relay-83ce2c681111). With no LAN candidate the
// one up is kept and the punch returns. The grace is set past the test's
// bound, since PreferLan holds for a LAN path within the grace (the spec's Reach) and a
// loaded machine stretches a loopback handshake past lanGrace.
func TestDirectPunchPrefersLAN(t *testing.T) {
	e, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck
	e.grace = time.Minute
	open := make(chan struct{})
	close(open)
	pub := quicPeer(t, open)
	pubTaken := make(chan struct{})
	var once sync.Once
	e.took = func(a netip.AddrPort) {
		if a == pub {
			once.Do(func() { close(pubTaken) })
		}
	}
	lan := quicPeer(t, pubTaken)
	e.lan = func(a netip.AddrPort) bool { return a == lan }
	tc := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13} // #nosec G402 -- test peers
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q, err := e.punch(ctx, []netip.AddrPort{pub, lan}, nil, tc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := q.RemoteAddr().(*net.UDPAddr).AddrPort(); got != lan {
		t.Fatalf("kept %v, want the LAN candidate %v (the non-LAN one is %v)", got, lan, pub)
	}
	_ = q.CloseWithError(0, "")
	e.took = nil
	e.lan = func(netip.AddrPort) bool { return false }
	e.grace = time.Millisecond // no LAN candidate: only the grace's wait for a LAN probe
	// The other peer never answers during the punch: of two non-LAN
	// connections up, the punch keeps the first its loop receives, which
	// goroutine scheduling orders, not the peers' handshakes (a peer gated
	// on the first one's Accept was kept once on a loaded runner, relay
	// 8a8ea47); DirectPunch.tla's trace check holds the loop to its model.
	pub = quicPeer(t, open)
	other := quicPeer(t, nil)
	q, err = e.punch(ctx, []netip.AddrPort{pub, other}, nil, tc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := q.RemoteAddr().(*net.UDPAddr).AddrPort(); got != pub {
		t.Fatalf("kept %v, want the one up %v", got, pub)
	}
	_ = q.CloseWithError(0, "")
}
