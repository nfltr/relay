// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
)

// slowConn delays every datagram it reads: a peer whose handshake ends
// after another candidate's.
type slowConn struct {
	net.PacketConn
	d time.Duration
}

func (c slowConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(b)
	time.Sleep(c.d)
	return n, a, err
}

// quicPeer is a QUIC server on loopback answering quiclink's ALPN,
// reading through a delay of d.
func quicPeer(t *testing.T, d time.Duration) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := newTestOrg(t).machine(t, "peer", nil, time.Hour, false)
	ln, err := quic.Listen(slowConn{pc, d}, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quiclink.ALPNChain, quiclink.ALPN}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = pc.Close() })
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
// later (within lanGrace): the punch keeps the LAN connection
// (DirectPunch.tla PreferLan, mutant first-wins); with no LAN candidate the
// first up is kept.
func TestDirectPunchPrefersLAN(t *testing.T) {
	e, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck
	pub, lan := quicPeer(t, 0), quicPeer(t, 20*time.Millisecond)
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
	q, err = e.punch(ctx, []netip.AddrPort{pub, lan}, nil, tc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := q.RemoteAddr().(*net.UDPAddr).AddrPort(); got != pub {
		t.Fatalf("kept %v, want the first up %v", got, pub)
	}
	_ = q.CloseWithError(0, "")
}
