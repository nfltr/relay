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
// handshake starts only once another candidate's ended (an event, not a
// delay: a loaded machine keeps the order).
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
// reads once gate closes; the channel it returns closes once a handshake
// with it ended.
func quicPeer(t *testing.T, gate <-chan struct{}) (netip.AddrPort, <-chan struct{}) {
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
	up := make(chan struct{})
	go func() {
		var once sync.Once
		for {
			q, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			once.Do(func() { close(up) })
			go func() { <-q.Context().Done() }()
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort(), up
}

// TestDirectPunchPrefersLAN: a non-LAN candidate answers first, a LAN one
// only after it (within the grace): the punch keeps the LAN connection
// (DirectPunch.tla PreferLan, mutant first-wins); with no LAN candidate the
// first up is kept. The grace is set past the test's bound, since
// PreferLan holds for a LAN path within the grace (the spec's Reach) and a
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
	pub, pubUp := quicPeer(t, open)
	lan, _ := quicPeer(t, pubUp)
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
	e.lan = func(netip.AddrPort) bool { return false }
	e.grace = time.Millisecond // no LAN candidate: only the grace's wait for a LAN probe
	pub, pubUp = quicPeer(t, open)
	other, _ := quicPeer(t, pubUp)
	q, err = e.punch(ctx, []netip.AddrPort{pub, other}, nil, tc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := q.RemoteAddr().(*net.UDPAddr).AddrPort(); got != pub {
		t.Fatalf("kept %v, want the first up %v", got, pub)
	}
	_ = q.CloseWithError(0, "")
}
