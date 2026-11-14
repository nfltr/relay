// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nfltr/relay/client/dgram"
)

// A PacketListener is every flow of its associations as one PacketConn:
// ReadFrom names the flow, WriteTo answers on it, a closed flow's address
// is net.ErrClosed. (The association here is in memory, its session what
// Listen's would carry.)
func TestPacketListenerFlows(t *testing.T) {
	p := &PacketListener{l: &Listener{addr: Addr{Target: "web/dns"}}, flows: map[uint64]*dgram.Conn{}}
	p.inbox, p.post = dgram.Pipe(64, p.l.addr, p.l.addr)
	s, c := net.Pipe()
	go func() {
		_ = dgram.Serve(context.Background(), s, dgram.Config{}, func() (net.Conn, error) { return p.flow("cli"), nil })
	}()
	cl := dgram.NewClient(c, dgram.Config{})
	defer cl.Close() //nolint:errcheck
	_ = p.SetReadDeadline(time.Now().Add(5 * time.Second))
	var flows []*dgram.Conn
	seen := map[uint64]bool{}
	for i := range 3 {
		f, err := cl.Dial(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.SetDeadline(time.Now().Add(5 * time.Second))
		flows = append(flows, f)
		if _, err := f.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 8)
		n, from, err := p.ReadFrom(buf)
		a, _ := from.(Addr)
		if err != nil || n != 1 || buf[0] != byte(i) || a.Target != "cli" || seen[a.Flow] {
			t.Fatalf("flow %d: %q from %v, %v", i, buf[:n], from, err)
		}
		seen[a.Flow] = true
		if _, err := p.WriteTo([]byte{'r', byte(i)}, from); err != nil {
			t.Fatal(err)
		}
		if n, err := f.Read(buf); err != nil || string(buf[:n]) != string([]byte{'r', byte(i)}) {
			t.Fatalf("reply %d: %q %v", i, buf[:n], err)
		}
	}
	if _, err := p.WriteTo(nil, Addr{Target: "cli", Flow: 99}); err != net.ErrClosed {
		t.Fatalf("WriteTo an unknown flow: %v", err)
	}
	if _, _, err := p.ReadFrom(make([]byte, 8)); err == nil {
		t.Fatal("ReadFrom with nothing sent returned a datagram")
	}
}

func TestDialDatagramUsage(t *testing.T) {
	d := &Dialer{}
	for _, o := range []DialOptions{{Early: true}} {
		if _, err := d.DialDatagram(t.Context(), "web/dns", o); CodeOf(err) != CodeUsage {
			t.Fatalf("%+v: %v", o, err)
		}
	}
}
