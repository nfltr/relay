// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// TestNF1ServiceDeclaresAndServes: a service under a capability address
// declares its rendezvous id, takes E2EE sessions only, and serves them
// through the listener's handshake to its target (nfltr
// docs/decisions/nf1-rendezvous-2026-11-13.md).
func TestNF1ServiceDeclaresAndServes(t *testing.T) {
	l, _, err := nf1.Mint("relay.example")
	if err != nil {
		t.Fatal(err)
	}
	target := echoServer(t)
	table, err := NewServiceTable([]Service{{Name: "clip", Kind: agentservices.TCP, E2EE: agentservices.E2EEOn, Target: target, NF1: l}})
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := agentservices.FindNF1(table.decls, l.Address().RID); !ok || d.Name != "clip" {
		t.Fatalf("decls %v lack the rid", table.decls)
	}
	targets := sessionTargets{services: table}
	if _, err := planOpen(&pb.TCPData{TargetAddr: "clip"}, targets, nil); err == nil {
		t.Fatal("a plain session to an nf1 service was planned")
	}
	p, err := planOpen(&pb.TCPData{TargetAddr: "clip", E2Ee: true, Answer: true}, targets, nil)
	if err != nil || p.kind != sessionNF1 || p.nf1 != l {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	tc, err := net.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	c, s := net.Pipe()
	go serveNF1(t.Context(), s, tc, p, slog.New(slog.DiscardHandler))
	conn, err := nf1.Handshake(t.Context(), c, l.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.(*tls.Conn).NetConn().Close() //nolint:errcheck
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "hi" {
		t.Fatalf("echo %q, %v", b, err)
	}
	for _, bad := range []Service{
		{Name: "a", Kind: agentservices.TCP, E2EE: agentservices.E2EEOff, Target: target, NF1: l},
		{Name: "a", Kind: agentservices.TCP, Target: target, NF1: l},
		{Name: "a", Kind: agentservices.TCP, E2EE: agentservices.E2EEOn, Target: target, NF1: l, Group: "db"},
	} {
		if _, err := NewServiceTable([]Service{bad}); err == nil {
			t.Errorf("NewServiceTable(%+v) accepted", bad)
		}
	}
}
