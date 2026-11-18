// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/link/peerlink/quiclink"
	"github.com/nfltr/quic-go"
)

// Trickle (nfltr docs/decisions/direct-paths-2026-11-11.md "Trickle",
// spec/DirectPunch.tla NoWait): no end waits for its relay's address
// check before its first candidates.

// silentUDP is a relay's UDP port that never answers (a relay without
// AGENT_LINK_QUIC_LISTEN): a QAD there runs to its 3 s bound.
func silentUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

// qadListen is a test relay's QAD listener on loopback. Its own
// Transport, closed at cleanup with every connection: a single-use
// listener (quic.ListenAddr) closed while a QAD connection is still open
// keeps its read loop running (quic-go stops it only when its last
// handler is gone at the listener's close), and a trickled QAD may still
// run when the test ends.
func qadListen(t *testing.T, cert tls.Certificate) *quic.Listener {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	ln, err := tr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{QADALPN}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = tr.Close(); _ = pc.Close() })
	return ln
}

// TestDirectSilentQADDelaysNoPunch: both ends' relay QAD is silent; the
// session goes direct on the host candidates well within the check's 3 s
// bound (before trickle: after it, at each end in turn).
func TestDirectSilentQADDelaysNoPunch(t *testing.T) {
	r := newDirectRig(t, DirectOn)
	if len(r.d.ep.hostCandidates()) == 0 {
		t.Skip("no non-loopback interface address: no host candidate to punch")
	}
	silent := silentUDP(t)
	r.relay = silent
	r.l.targets.qad = tunnelQAD(silent)
	start := time.Now()
	_, tc, events := r.session(t)
	echo(t, tc, 1<<16, func() { waitPath(t, events, PathDirect) })
	if d := time.Since(start); d >= 2*time.Second {
		t.Fatalf("direct after %v, want well within the QAD bound (3 s): a punch waited for the address check", d)
	}
}

// TestGatherKeepsRoomForTheSlowCandidates: a machine with more interface
// addresses than MaxCandidates still sends its reflexive candidate (it
// led the list before trickle; the first trickle cut it off on a Mac
// with six IPv6 addresses).
func TestGatherKeepsRoomForTheSlowCandidates(t *testing.T) {
	e, err := NewDirectEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck
	for i := range quiclink.MaxCandidates + 2 {
		e.hosts = append(e.hosts, netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, byte(i + 1)}), 4242))
	}
	refl := netip.MustParseAddrPort("203.0.113.5:4242")
	first, late := e.gather(func() []netip.AddrPort { return []netip.AddrPort{refl} })
	var buf bytes.Buffer
	sendLate(&buf, first, late)
	var c directCandidates
	if err := json.Unmarshal(buf.Bytes(), &c); err != nil {
		t.Fatalf("late line %q: %v", buf.String(), err)
	}
	if len(first)+len(c.Candidates) != quiclink.MaxCandidates || !slices.Contains(c.Candidates, refl.String()) {
		t.Fatalf("first %v, late %v: want the reflexive candidate trickled within %d", first, c.Candidates, quiclink.MaxCandidates)
	}
}
