// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// groupRig is two instances of blob@db, agent web on machines web-1 and
// web-2 (direct on), and a client whose relay routes the group dial's
// opens to web-1 unless excluded (an adversary's pick: the instance that
// does not hold the session) and <machine>.web to that machine.
type groupRig struct {
	inst   map[string]*linkSessions // by machine name
	d      *DirectClient
	client testMachine
	mu     sync.Mutex
	picks  [][]string // each group open's exclude
	routes []string   // each reserved-service open's agent
}

func newGroupRig(t *testing.T) *groupRig {
	t.Helper()
	o := newTestOrg(t)
	qad, target := qadServer(t), echoTarget(t)
	g := &groupRig{inst: map[string]*linkSessions{}, client: testMachine{o: o, cert: o.machine(t, "laptop", []string{"db"}, time.Hour, false)}}
	for _, m := range []string{"web-1", "web-2"} {
		table, err := NewServiceTable([]Service{{Name: "blob", Kind: agentservices.TCP, Target: target, E2EE: agentservices.E2EEOn,
			Org: o.agentOrg(o.machine(t, m, []string{"db"}, time.Hour, false)), AllowGroups: []string{"db"}, Group: "db", Direct: DirectOn}})
		if err != nil {
			t.Fatal(err)
		}
		d := table.direct
		d.ep.loopback = true
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = d.node.Drain(ctx)
			_ = d.ep.Close()
		})
		g.inst[m] = &linkSessions{ctx: t.Context(), targets: sessionTargets{services: table, agent: "web", qad: tunnelQAD(qad)},
			logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}}
	}
	var err error
	g.d, err = NewDirectClient(DirectClientConfig{Machine: g.client,
		Relayed: func(_ context.Context, agent string) (net.Conn, error) {
			g.mu.Lock()
			g.routes = append(g.routes, agent)
			g.mu.Unlock()
			m, _, _ := strings.Cut(agent, ".")
			return g.open(t, m, DirectServiceName)
		},
		RelayedGroup: func(_ context.Context, name string, exclude []string) (net.Conn, error) {
			if name != "blob@db" {
				return nil, fmt.Errorf("group open of %q", name)
			}
			g.mu.Lock()
			g.picks = append(g.picks, slices.Clone(exclude))
			g.mu.Unlock()
			m := "web-1"
			if slices.Contains(exclude, m) {
				m = "web-2"
			}
			return g.open(t, m, "blob")
		},
		QADTLS: func(string) *tls.Config { return &tls.Config{InsecureSkipVerify: true} }}) // #nosec G402 -- a test's relay
	if err != nil {
		t.Fatal(err)
	}
	g.d.ep.loopback = true
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = g.d.node.Drain(ctx)
		_ = g.d.ep.Close()
	})
	return g
}

// open is a relayed session to machine's agent's target, answered.
func (g *groupRig) open(t *testing.T, machine, target string) (net.Conn, error) {
	l := g.inst[machine]
	if l == nil {
		return nil, fmt.Errorf("no machine %q", machine)
	}
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: target, E2Ee: true, Answer: true})
	if err != nil {
		return nil, err
	}
	go l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		return nil, fmt.Errorf("answer %v, %v", a, err)
	}
	return c, nil
}

// TestDirectGroupDialGoesDirectToItsInstance: a session of blob@db that
// the relay put on web-2 goes direct to web-2, never to web-1: the first
// control exchange on the group's route meets web-1 (the relay's pick),
// refuses its certificate and excludes it, web-2's offer names its agent,
// and the re-attach after the direct path dies opens web-2.web.
func TestDirectGroupDialGoesDirectToItsInstance(t *testing.T) {
	g := newGroupRig(t)
	first, err := g.open(t, "web-2", "blob")
	if err != nil {
		t.Fatal(err)
	}
	ds := g.d.Start(first)
	cfg := g.d.punchTLS(&directPair{machine: "web-2"})
	BindServiceTLS(cfg, GroupALPN("blob", "db"))
	tc := tls.Client(ds.Conn(), cfg)
	if err := tc.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tc.Close() })
	events := make(chan PathEvent, 16)
	if err := ds.Run(tc.ConnectionState(), "blob@db", tc.ConnectionState().PeerCertificates[0].Subject.CommonName, "blob", DirectOn,
		func(e PathEvent) { events <- e }); err != nil {
		t.Fatal(err)
	}
	echo(t, tc, 2<<20, func() {
		e := waitPath(t, events, PathDirect)
		if want := g.inst["web-2"].targets.services.direct.ep.tr.Conn.LocalAddr().(*net.UDPAddr).Port; int(e.Peer.Port()) != want {
			t.Errorf("direct to port %d, want web-2's %d", e.Peer.Port(), want)
		}
		p := g.d.pair("blob@db", "web-2")
		if r := p.routeOf(); r != "web-2.web" {
			t.Errorf("route %q, want web-2.web", r)
		}
		p.mu.Lock()
		_ = p.q.CloseWithError(0, "the direct path dies")
		p.mu.Unlock()
		if e := waitPath(t, events, PathRelayed); e.Reason != ReasonDirectLost {
			t.Fatalf("fallback reason %q", e.Reason)
		}
	})
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.picks) != 2 || len(g.picks[0]) != 0 || !slices.Equal(g.picks[1], []string{"web-1"}) {
		t.Errorf("group opens' excludes %q, want none then web-1", g.picks)
	}
	for _, r := range g.routes {
		if r != "web-2.web" {
			t.Errorf("a reserved-service open to %q, want only web-2.web", r)
		}
	}
	if len(g.routes) == 0 {
		t.Error("no re-attach through web-2.web")
	}
	if n := len(g.inst["web-1"].targets.services.direct.sessions); n != 0 {
		t.Errorf("web-1 holds %d direct sessions", n)
	}
	if st := g.d.Stats(); st.Punches["ok"] != 1 || st.Punches[ReasonRefusedCert] != 0 {
		t.Errorf("punches %v", st.Punches)
	}
}
