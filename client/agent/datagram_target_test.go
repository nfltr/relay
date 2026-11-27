// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/nfltr/link/peerlink"
	"github.com/nfltr/relay/client/dgram"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// A udp service's session is an association to its target: one name
// served as tcp and udp, the session routed by kind (<name>+udp), each
// flow a socket of its own; a plain session to the stream name is not
// the datagram service's.
func TestDatagramServiceSession(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	table, err := NewServiceTable([]Service{
		{Name: "dns", Kind: agentservices.TCP, Target: echoTarget(t), E2EE: agentservices.E2EEOff},
		{Name: "dns", Kind: agentservices.UDP, Target: pc.LocalAddr().String(), E2EE: agentservices.E2EEOff},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := table.Declaration(); got != "dns=tcp+plain,dns=udp+plain" {
		t.Fatalf("declaration %q", got)
	}
	l := &linkSessions{ctx: t.Context(), targets: sessionTargets{services: table, agent: "web"}, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: agentservices.DatagramTarget("dns"), Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		t.Fatalf("answer %v, %v", a, err)
	}
	cl := dgram.NewClient(c, dgram.Config{})
	defer cl.Close() //nolint:errcheck
	for i := range 3 {
		f, err := cl.Dial(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.SetDeadline(time.Now().Add(5 * time.Second))
		msg := []byte{'q', byte(i)}
		if _, err := f.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		n, err := f.Read(buf)
		if err != nil || string(buf[:n]) != string(msg) {
			t.Fatalf("flow %d: %q %v", i, buf[:n], err)
		}
	}
	if st := cl.Stats(); st.Flows != 3 || st.Refused != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// A revocation of a udp service's session names itself (lane UDPFIX): the
// agent's cut (an organisation admission ended, an address replaced)
// tells each open flow why before the session ends, so the client's
// flow_close says "revoked", not "reset"; any other target is left to
// the reset.
func TestRevokeDatagramsTellsFlows(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	target, _, err := dialDatagram(t.Context(), pc.LocalAddr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, c := net.Pipe()
	go func() { _ = peerlink.Join(s, target) }()
	cl := dgram.NewClient(c, dgram.Config{})
	defer cl.Close() //nolint:errcheck
	f, err := cl.Dial(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if _, err := f.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(buf); err != nil {
		t.Fatal(err)
	}
	if !revokeDatagrams(target) {
		t.Fatal("a udp service's target was not revoked")
	}
	if _, err := f.Read(buf); err == nil || f.Reason() != dgram.ReasonRevoked {
		t.Fatalf("after the revocation: read %v, reason %v; want an end, ReasonRevoked", err, f.Reason())
	}
	select {
	case <-cl.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the session did not end after the revocation")
	}
	a, b := net.Pipe()
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck
	if revokeDatagrams(a) {
		t.Fatal("a stream target taken for a udp service's")
	}
}

// A udp service's sessions share its dgram.Service (lane NF1UDPBOUND):
// the table hands every session's association the service's one bound, so
// a second session past it is refused full, and its counters (the serving
// side's drops) are the service's.
func TestDatagramServiceSharedAcrossSessions(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() { // a UDP echo
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	svc := &dgram.Service{MaxFlows: 1}
	table, err := NewServiceTable([]Service{{Name: "dns", Kind: agentservices.UDP, Target: pc.LocalAddr().String(), Datagrams: svc}})
	if err != nil {
		t.Fatal(err)
	}
	e := table.byName[agentservices.Decl{Name: "dns", Kind: agentservices.UDP}.Target()]
	if e.dgram != svc {
		t.Fatal("the table did not keep the service's Datagrams")
	}
	open := func() *dgram.Conn {
		target, _, err := dialDatagram(t.Context(), e.addr, e.dgram)
		if err != nil {
			t.Fatal(err)
		}
		s, c := net.Pipe()
		go func() { _ = peerlink.Join(s, target) }()
		cl := dgram.NewClient(c, dgram.Config{})
		t.Cleanup(func() { _ = cl.Close() })
		f, err := cl.Dial(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("q")); err != nil {
			t.Fatal(err)
		}
		return f
	}
	first := open()
	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := first.Read(make([]byte, 16)); err != nil {
		t.Fatalf("the first session's flow: %v", err) // its open taken before the second's
	}
	second := open()
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 16)); err == nil || second.Reason() != dgram.ReasonFull {
		t.Fatalf("the second session's flow: %v, reason %v; want refused full", err, second.Reason())
	}
	if st := svc.Stats(); st.Live != 1 || st.FlowsFull != 1 {
		t.Fatalf("service %+v", st)
	}
	other, err := NewServiceTable([]Service{{Name: "dns", Kind: agentservices.UDP, Target: pc.LocalAddr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	if other.byName[agentservices.Decl{Name: "dns", Kind: agentservices.UDP}.Target()].dgram == nil {
		t.Fatal("no default Datagrams for a udp service")
	}
}
