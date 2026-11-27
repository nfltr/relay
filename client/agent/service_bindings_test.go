// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// The bindings spec/proverif/e2ee_tcp.pv's services by name rely on
// (queries 30-35), against the real code: each BIND:org.* the model lists
// has one row here that changes just what a relay can change of an honest
// session (the service it routes the session to, the protocol it offers)
// and requires a refusal. `make spec-bindings`.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/internal/modelbind"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// svcRig is agent web's sessions: pg published under group (when set) and
// vault published under none, both in organisation mode, its certificate
// in groups; a client in db.
type svcRig struct {
	l    *linkSessions
	org  *fakeOrg
	pool *x509.CertPool
	cli  tls.Certificate
}

func newSvcRig(t *testing.T, groups []string, group string) svcRig {
	t.Helper()
	o := newTestOrg(t)
	org := o.agentOrg(o.machine(t, "web", groups, time.Hour, false))
	svc := func(name, group string) Service {
		return Service{Name: name, Kind: agentservices.TCP, Target: echoTarget(t), E2EE: agentservices.E2EEOn, Org: org, Group: group}
	}
	table, err := NewServiceTable([]Service{svc("pg", group), svc("vault", "")})
	if err != nil {
		t.Fatal(err)
	}
	return svcRig{l: &linkSessions{ctx: t.Context(), targets: sessionTargets{services: table, agent: "web"}, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}},
		org: org, pool: o.pool, cli: o.machine(t, "cli", []string{"db"}, time.Hour, false)}
}

// session opens a session the relay routed to target, offers protos (no
// check of the negotiated one: the agent's half alone) and echoes once.
func (r svcRig) session(t *testing.T, target string, protos ...string) error {
	t.Helper()
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: target, E2Ee: true, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go r.l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		return fmt.Errorf("answer %v, %v", a, err)
	}
	tc := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.pool, ServerName: "web.org.internal", Certificates: []tls.Certificate{r.cli}, NextProtos: protos})
	defer tc.Close() //nolint:errcheck
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(tc, "ping\n"); err != nil {
		return err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(tc, buf); err != nil {
		return err
	}
	if string(buf) != "ping\n" {
		t.Fatalf("echo %q", buf)
	}
	return nil
}

// handshake is session's TLS handshake alone (a datagram session's bytes
// are its association's frames).
func (r svcRig) handshake(t *testing.T, target string, protos ...string) error {
	t.Helper()
	s, c := sessionPair(t)
	h, err := dataplane.OpenHeader(&pb.TCPData{TargetAddr: target, E2Ee: true, Answer: true})
	if err != nil {
		t.Fatal(err)
	}
	go r.l.accept("", h, s)
	if a, err := dataplane.ReadAnswer(c); err != nil || a.GetReason() != 0 {
		return fmt.Errorf("answer %v, %v", a, err)
	}
	tc := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.pool, ServerName: "web.org.internal", Certificates: []tls.Certificate{r.cli}, NextProtos: protos})
	defer tc.Close() //nolint:errcheck
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return err
	}
	// TLS 1.3: the agent's verdict on the client (its certificate, the
	// protocol) arrives after the client's handshake; one read sees it.
	_ = tc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := tc.Read(make([]byte, 1)); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}

// served requires err nil (what) and refused requires an error.
func served(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: refused (%v), want served", what, err)
	}
}

func refused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: served, want refused", what)
	}
}

// negotiating is a TLS server on a pipe that negotiates protos; the
// client's handshake error with cfg.
func negotiating(t *testing.T, cfg *tls.Config, protos ...string) error {
	t.Helper()
	o := newTestOrg(t)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() {
		srv := tls.Server(b, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{o.machine(t, "web", nil, time.Hour, false)}, NextProtos: protos})
		_ = srv.Handshake()
		_ = b.Close()
	}()
	cfg.RootCAs, cfg.ServerName = o.pool, "web.org.internal"
	tc := tls.Client(a, cfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	return tc.Handshake()
}

var serviceBindings = map[string]func(t *testing.T){
	// The ALPN name, at both ends. The agent: a session routed to pg serves
	// web/pg only, not web/vault (the relay routing a dial of vault to pg),
	// not another agent's pg, not a client that names no service (the hard
	// cut). The client: a server that negotiates no protocol is refused.
	"org.service": func(t *testing.T) {
		r := newSvcRig(t, []string{"db"}, "db")
		served(t, "web/pg", r.session(t, "pg", MachineALPN("web", "pg")))
		served(t, "m.web/pg", r.session(t, "pg", MachineALPN("m.web", "pg")))
		refused(t, "web/vault routed to pg", r.session(t, "pg", MachineALPN("web", "vault")))
		refused(t, "web/pg routed to vault", r.session(t, "vault", MachineALPN("web", "pg")))
		refused(t, "other/pg", r.session(t, "pg", MachineALPN("other", "pg")))
		refused(t, "no protocol", r.session(t, "pg"))
		cfg := &tls.Config{MinVersion: tls.VersionTLS13}
		BindServiceTLS(cfg, MachineALPN("web", "pg"))
		if err := negotiating(t, cfg.Clone(), MachineALPN("web", "pg")); err != nil {
			t.Fatalf("the client refused its own protocol: %v", err)
		}
		if err := negotiating(t, cfg.Clone()); !errors.Is(err, ErrServiceNotNegotiated) {
			t.Fatalf("the client took a server that negotiated no protocol (%v)", err)
		}
	},
	// The group, in the certificate's OU: the agent refuses to start a
	// service published under a group its certificate lacks, and refuses
	// <service>@<group> once a renewed certificate lacks the group.
	"org.group": func(t *testing.T) {
		o := newTestOrg(t)
		org := o.agentOrg(o.machine(t, "web", []string{"db"}, time.Hour, false))
		if _, err := NewServiceTable([]Service{{Name: "pg", Kind: agentservices.TCP, Target: "localhost:1", E2EE: agentservices.E2EEOn, Org: org, Group: "ops"}}); err == nil {
			t.Fatal("NewServiceTable published pg under ops, a group the certificate lacks")
		}
		r := newSvcRig(t, []string{"db"}, "db")
		served(t, "pg@db", r.session(t, "pg", GroupALPN("pg", "db")))
		r.org.cert = r.org.o.machine(t, "web", []string{"ops"}, time.Hour, false)
		refused(t, "pg@db, the certificate renewed without db", r.session(t, "pg", GroupALPN("pg", "db")))
	},
	// The kind, in the protocol's prefix: web serves pg as a stream and as
	// a datagram service, both under db. A session routed to the datagram
	// pg serves only the datagram protocol, a stream one only the stream
	// protocol (the relay routing a dial of one kind to the other); the
	// client refuses a server that negotiated the other kind.
	"org.kind": func(t *testing.T) {
		o := newTestOrg(t)
		org := o.agentOrg(o.machine(t, "web", []string{"db"}, time.Hour, false))
		svc := func(kind agentservices.Kind, target string) Service {
			return Service{Name: "pg", Kind: kind, Target: target, E2EE: agentservices.E2EEOn, Org: org, Group: "db"}
		}
		table, err := NewServiceTable([]Service{svc(agentservices.TCP, echoTarget(t)), svc(agentservices.UDP, "127.0.0.1:9")})
		if err != nil {
			t.Fatal(err)
		}
		r := svcRig{l: &linkSessions{ctx: t.Context(), targets: sessionTargets{services: table, agent: "web"}, logger: slog.New(slog.DiscardHandler), growth: &tcpStreamGrowth{}},
			org: org, pool: o.pool, cli: o.machine(t, "cli", []string{"db"}, time.Hour, false)}
		dg := agentservices.DatagramTarget("pg")
		served(t, "web/pg stream", r.session(t, "pg", MachineALPN("web", "pg")))
		served(t, "web/pg datagram", r.handshake(t, dg, DatagramALPN(MachineALPN("web", "pg"))))
		served(t, "pg@db datagram", r.handshake(t, dg, DatagramALPN(GroupALPN("pg", "db"))))
		refused(t, "the stream web/pg routed to the datagram pg", r.handshake(t, dg, MachineALPN("web", "pg")))
		refused(t, "the stream pg@db routed to the datagram pg", r.handshake(t, dg, GroupALPN("pg", "db")))
		refused(t, "the datagram web/pg routed to the stream pg", r.handshake(t, "pg", DatagramALPN(MachineALPN("web", "pg"))))
		refused(t, "the datagram pg@db routed to the stream pg", r.handshake(t, "pg", DatagramALPN(GroupALPN("pg", "db"))))
		// A relay that rewrote the offer: the server negotiated the stream
		// protocol (BindServiceTLS's VerifyConnection check).
		if err := checkNegotiated(tls.ConnectionState{NegotiatedProtocol: MachineALPN("web", "pg")}, DatagramALPN(MachineALPN("web", "pg"))); !errors.Is(err, ErrServiceNotNegotiated) {
			t.Fatalf("the datagram client took a server that negotiated the stream protocol (%v)", err)
		}
	},
	// The publish: <service>@<group> is served only for the group the
	// service is published under: not pg@db for a pg published under ops
	// (the certificate in both), not vault@db for a vault under none.
	"org.publish": func(t *testing.T) {
		r := newSvcRig(t, []string{"db", "ops"}, "ops")
		served(t, "pg@ops", r.session(t, "pg", GroupALPN("pg", "ops")))
		refused(t, "pg@db, pg published under ops", r.session(t, "pg", GroupALPN("pg", "db")))
		refused(t, "vault@db, vault published under none", r.session(t, "vault", GroupALPN("vault", "db")))
	},
}

// TestServiceModelBindings runs every row, and fails when the model's
// BIND:org ids and the rows differ.
func TestServiceModelBindings(t *testing.T) {
	src, err := os.ReadFile(directBindModel)
	if err != nil {
		t.Fatal(err)
	}
	rows := slices.Sorted(maps.Keys(serviceBindings))
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:(org\.[a-z0-9.]+)`), rows); err != nil {
		t.Fatalf("%s: %v", directBindModel, err)
	}
	for _, id := range rows {
		t.Run(id, serviceBindings[id])
	}
}
