// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nfltr/quic-go"
	"github.com/nfltr/relay/client/nf1"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// Services under one agent identity. The relay names a
// session's service in the open frame's target_addr (pb.TCPData has no
// field of its own for it); the agent looks the name up in its
// ServiceTable, its local allow-list, and dials only that service's
// target.

// Service is one named service of an agent.
type Service struct {
	Name   string             // agentservices.ValidName
	Kind   agentservices.Kind // HTTP: E2EE sessions; TCP: raw sessions
	Target string             // HTTP: backend URL (http or https); TCP: host:port, or unix:/abs/path (a unix socket only this table dials)
	// E2EE of a TCP service: On, its sessions are TLS in organisation mode
	// (Org, required; a plain session is refused); Off, plain bytes only;
	// Default, either as the relay's policy resolves it, and a session
	// that is end to end encrypted is refused (no Org).
	E2EE agentservices.E2EE
	// Cert, when set, is the certificate an http service's E2EE share
	// sessions end with instead of the tunnel's (Tunnel.E2EE): an http
	// service whose share takes the tunnel's ACME certificate beside
	// another under one agent identity. A tcp service takes none.
	Cert *E2EESetup
	// Org puts a TCP service with E2EE On in organisation mode, its only
	// end-to-end encrypted mode: its sessions end TLS with the
	// organisation's machine certificate and admit a client certificate in
	// one of AllowGroups (Org.CheckClient), nothing else
	// (spec/proverif/e2ee_tcp.pv mutant downgrade-any-client).
	Org Org
	// AllowGroups are the organisation groups whose machines Org admits;
	// required with Org, refused without it.
	AllowGroups []string
	// Group publishes an organisation-mode service under one organisation
	// group, dialled as <service>@<group> (agentservices.Decl.Group): the
	// group must be in this machine's certificate (NewServiceTable refuses
	// it otherwise), and a session for <service>@<group> is served only
	// for the group the service is published under (service_alpn.go;
	// e2ee_tcp.pv mutant agent-no-publish-check). "": a machine dial only.
	Group string
	// Direct lets an organisation-mode service's sessions move to a direct
	// path when their client asks (direct.go; DirectOff, the default:
	// relayed only, no address of this machine sent). The table then
	// serves DirectServiceName too.
	Direct DirectMode
	// NF1 serves the service under a capability address (nf1...): a tcp
	// service with E2EE On and no Org, Group, AllowGroups or Direct. Its
	// sessions run the listener's rendezvous answer, pinned TLS and proof
	// before one byte reaches Target (package nf1; nfltr
	// docs/decisions/nf1-rendezvous-2026-11-13.md); the relay finds the
	// service by the address's rendezvous id, declared with it.
	NF1 *nf1.Listener
	// Public declares the service public (agentservices.Decl.Public): the
	// relay may route anonymous visitors of a public TCP endpoint to it, as
	// plain bytes. A tcp service with E2EE Off only.
	Public bool
}

// ServiceTable is the services an agent serves under its identity: the
// only targets its ConnectTCP sessions reach. A session that names no
// service of the table, a service of the wrong kind or a raw address is
// refused (closed, logged, counted), never dialled: the agent is no open
// forwarder. Build it before the tunnel runs; it is read-only after.
type ServiceTable struct {
	byName    map[string]*tableService
	decls     []agentservices.Decl
	direct    *directServer // the direct services' (DirectServiceName); nil: none
	refused   atomic.Uint64
	onSession func(Session)
}

// Caller is the machine that opened a session, as the relay authenticated
// it (pb.CallerIdentity): never anything the caller sent. Machine, Group
// and Account are ids; MachineName is for display only (a rename changes
// it).
type Caller struct {
	Machine, Group, Account, MachineName string
}

// Session is a session the relay opened to one of the table's services,
// as OnSession reports it once the table admitted it.
type Session struct {
	Service string
	caller  *pb.CallerIdentity
}

// Caller is who opened s; ok is false when the relay named no caller (a
// share visitor's session, or a relay that does not send one).
func (s Session) Caller() (c Caller, ok bool) {
	if s.caller.GetMachineId() == "" {
		return Caller{}, false
	}
	return Caller{Machine: s.caller.GetMachineId(), Group: s.caller.GetGroupId(),
		Account: s.caller.GetAccount(), MachineName: s.caller.GetMachineName()}, true
}

// OnSession calls f with each session the table admits, before its target
// is dialled (f must not block). Call it before the tunnel runs.
func (t *ServiceTable) OnSession(f func(Session)) { t.onSession = f }

type tableService struct {
	kind    agentservices.Kind
	e2ee    agentservices.E2EE
	network string   // TCP: "tcp" or "unix"
	addr    string   // TCP: the address dialled
	backend string   // HTTP: the backend URL
	shares  []string // share codes whose policy wrap enforces
	wrap    func(http.Handler) http.Handler
	cert    *e2eeTLSConfig // Service.Cert; nil: the tunnel's
	org     Org            // Service.Org: organisation mode; nil: no E2EE tcp session
	groups  []string       // Service.AllowGroups
	group   string         // Service.Group: published under it
	nf1     *nf1.Listener  // Service.NF1: served under a capability address
}

// NewServiceTable validates services and returns their table.
func NewServiceTable(services []Service) (*ServiceTable, error) {
	if len(services) == 0 || len(services) > agentservices.MaxServices {
		return nil, fmt.Errorf("services: want 1 to %d, got %d", agentservices.MaxServices, len(services))
	}
	t := &ServiceTable{byName: make(map[string]*tableService, len(services))}
	for _, s := range services {
		if !agentservices.ValidName(s.Name) {
			return nil, fmt.Errorf("service %q: invalid name (a DNS label starting with a letter)", s.Name)
		}
		if t.byName[s.Name] != nil {
			return nil, fmt.Errorf("service %q: declared twice", s.Name)
		}
		if s.Name == DirectServiceName {
			return nil, fmt.Errorf("service %q: the name is reserved for direct paths", s.Name)
		}
		if s.Direct != DirectOff && (s.Org == nil || s.Direct != DirectOn && s.Direct != DirectPublic) {
			return nil, fmt.Errorf("service %q: direct %q needs organisation mode (want %q or %q)", s.Name, s.Direct, DirectOn, DirectPublic)
		}
		e := &tableService{kind: s.Kind, e2ee: s.E2EE}
		if s.Cert != nil {
			e.cert = s.Cert.cfg
		}
		if s.E2EE != agentservices.E2EEDefault && (s.Kind != agentservices.TCP || (s.E2EE != agentservices.E2EEOn && s.E2EE != agentservices.E2EEOff)) {
			return nil, fmt.Errorf("service %q: e2ee %q (want %q or %q on a tcp service)", s.Name, s.E2EE, agentservices.E2EEOn, agentservices.E2EEOff)
		}
		if s.Cert != nil && s.Kind != agentservices.HTTP {
			return nil, fmt.Errorf("service %q: a certificate of its own needs an http service (a tcp service's E2EE is the organisation's)", s.Name)
		}
		if err := checkOrgService(s); err != nil {
			return nil, err
		}
		if err := checkPublish(s); err != nil {
			return nil, err
		}
		if s.NF1 != nil && (s.Kind != agentservices.TCP || s.E2EE != agentservices.E2EEOn || s.Org != nil || s.Group != "" || len(s.AllowGroups) > 0 || s.Direct != DirectOff) {
			return nil, fmt.Errorf("service %q: a capability address (nf1) needs a tcp service with e2ee on and no organisation, group or direct", s.Name)
		}
		if s.Public && (s.Kind != agentservices.TCP || s.E2EE != agentservices.E2EEOff) {
			return nil, fmt.Errorf("service %q: a public service needs a tcp service with e2ee off (its visitors' bytes are plain at the relay)", s.Name)
		}
		e.org, e.groups, e.group, e.nf1 = s.Org, s.AllowGroups, s.Group, s.NF1
		switch s.Kind {
		case agentservices.TCP:
			e.network, e.addr = "tcp", s.Target
			if path, ok := strings.CutPrefix(s.Target, "unix:"); ok {
				if !filepath.IsAbs(path) {
					return nil, fmt.Errorf("service %q: target %q: a unix socket path must be absolute", s.Name, s.Target)
				}
				e.network, e.addr = "unix", path
			} else if _, port, err := net.SplitHostPort(s.Target); err != nil || port == "" {
				return nil, fmt.Errorf("service %q: target %q is not host:port or unix:/path", s.Name, s.Target)
			}
		case agentservices.HTTP:
			u, err := url.Parse(s.Target)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return nil, fmt.Errorf("service %q: target %q is not an http(s) URL", s.Name, s.Target)
			}
			e.backend = s.Target
		default:
			return nil, fmt.Errorf("service %q: unknown kind %q", s.Name, s.Kind)
		}
		t.byName[s.Name] = e
		d := agentservices.Decl{Name: s.Name, Kind: s.Kind, E2EE: s.E2EE, Group: s.Group, Public: s.Public}
		if s.NF1 != nil {
			d.NF1 = s.NF1.Address().RID
		}
		t.decls = append(t.decls, d)
	}
	if err := t.addDirect(services); err != nil {
		return nil, err
	}
	return t, nil
}

// addDirect serves DirectServiceName when a service has Direct: in
// organisation mode (the first direct service's Org), its allow groups
// every direct service's.
func (t *ServiceTable) addDirect(services []Service) error {
	var org Org
	var groups []string
	modes := map[string]DirectMode{}
	for _, s := range services {
		if s.Direct == DirectOff {
			continue
		}
		if org == nil {
			org = s.Org
		}
		modes[s.Name] = s.Direct
		for _, g := range s.AllowGroups {
			if !slices.Contains(groups, g) {
				groups = append(groups, g)
			}
		}
	}
	if org == nil {
		return nil
	}
	if len(t.decls) >= agentservices.MaxServices {
		return fmt.Errorf("services: direct paths take one of the %d services", agentservices.MaxServices)
	}
	d, err := newDirectServer(org, groups, modes)
	if err != nil {
		return err
	}
	t.direct = d
	t.byName[DirectServiceName] = &tableService{kind: agentservices.TCP, e2ee: agentservices.E2EEOn, network: networkDirect, org: org, groups: groups}
	t.decls = append(t.decls, agentservices.Decl{Name: DirectServiceName, Kind: agentservices.TCP, E2EE: agentservices.E2EEOn})
	return nil
}

// Continue gives t prev's direct paths when both serve the same direct
// services, before t serves: a table built for a new relay connection
// (nfltr builds one per connection) keeps the sessions that re-attach
// after the old connection died, the UDP socket and its NAT mapping; t's
// own stop. prev keeps serving its connection's sessions.
func (t *ServiceTable) Continue(prev *ServiceTable) {
	if t == nil || prev == nil || t.direct == nil || prev.direct == nil || t.direct == prev.direct {
		return
	}
	n, o := t.direct, prev.direct
	if !slices.Equal(n.groups, o.groups) || !maps.Equal(n.modes, o.modes) {
		return // ponytail: prev's lives on with its sessions; a relay that changes a service's mode mid-process leaves one socket
	}
	t.direct = o
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = n.node.Drain(ctx)
	_ = n.ep.Close()
}

// DirectTransport is the UDP socket of the table's direct paths, for the
// agent link's QUIC (QUICDialer.Transport); nil: no direct service.
func (t *ServiceTable) DirectTransport() *quic.Transport {
	if t == nil || t.direct == nil {
		return nil
	}
	return t.direct.ep.tr
}

func (t *ServiceTable) directServer() *directServer {
	if t == nil {
		return nil
	}
	return t.direct
}

// networkDirect: the reserved service's sessions are served in process.
const networkDirect = "direct"

// RequireSharePolicy makes every E2EE request to service satisfy the
// credential policy of its share code, as E2EESetup.RequireSharePolicy does
// for a single-service agent, for that service only: another service's
// sessions are not checked against it, and this service's sessions never
// pass on another service's credentials. Call it before the tunnel runs.
func (t *ServiceTable) RequireSharePolicy(service, code string, p SharePolicy) error {
	e := t.byName[service]
	if e == nil || e.kind != agentservices.HTTP {
		return fmt.Errorf("share policy: no http service %q", service)
	}
	check, err := newSharePolicyCheck(code, p)
	if err != nil {
		return err
	}
	e.wrap = composeWraps(e.wrap, check.wrap)
	e.shares = append(e.shares, code)
	return nil
}

// Refused is how many sessions the table has refused.
// allow:wrapper — the counter is the table's own.
func (t *ServiceTable) Refused() uint64 { return t.refused.Load() }

func (t *ServiceTable) shareCodes() []string {
	var codes []string
	for _, d := range t.decls {
		codes = append(codes, t.byName[d.Name].shares...)
	}
	return codes
}

// ServiceRefusedError is why a session was refused: what it named and
// why that is no target of the table.
type ServiceRefusedError struct {
	Target string // the open frame's target_addr
	E2EE   bool
	Reason string
	// Answer is the session answer's reason (dataplane.WriteAnswer).
	Answer relayv1.ErrorReason
}

// allow:wrapper — the error interface.
func (e *ServiceRefusedError) Error() string {
	return fmt.Sprintf("session refused: target %q (e2ee=%v): %s", e.Target, e.E2EE, e.Reason)
}

// resolve returns the service a session names. An E2EE session needs the
// agent to terminate E2EE and a service that is http, or tcp without
// E2EE Off for the owner's session (connect: it asks for an answer; an
// E2EE share session, the SNI router's, never does); a raw session needs a
// tcp service without E2EE On.
func (t *ServiceTable) resolve(target string, e2ee, terminatesE2EE, connect bool) (*tableService, error) {
	refuse := func(answer relayv1.ErrorReason, reason string) (*tableService, error) {
		t.refused.Add(1)
		return nil, &ServiceRefusedError{Target: target, E2EE: e2ee, Reason: reason, Answer: answer}
	}
	e := t.byName[target]
	switch {
	case e == nil:
		return refuse(relayv1.ErrorReason_ERROR_REASON_UNKNOWN_SERVICE, "no such service")
	case e2ee && !terminatesE2EE && e.cert == nil && e.org == nil && e.nf1 == nil:
		return refuse(relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE, "the agent does not terminate end-to-end TLS")
	case e2ee && e.kind == agentservices.TCP && !connect:
		return refuse(relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE, "an end-to-end encrypted share session needs an http service")
	case e2ee && e.kind == agentservices.TCP && e.org == nil && e.nf1 == nil:
		// Only organisation mode is end to end encrypted (E2EE Off, or a
		// Default service the relay's policy made plain).
		return refuse(relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE, "the service is not end-to-end encrypted (not in organisation mode)")
	case !e2ee && e.kind != agentservices.TCP:
		return refuse(relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED, "a raw TCP session needs a tcp service")
	case !e2ee && e.e2ee == agentservices.E2EEOn:
		return refuse(relayv1.ErrorReason_ERROR_REASON_E2EE_REQUIRED, "the service takes end-to-end encrypted sessions only")
	}
	return e, nil
}

// composeWraps applies outer around inner; either may be nil.
func composeWraps(outer, inner func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	switch {
	case outer == nil:
		return inner
	case inner == nil:
		return outer
	}
	return func(next http.Handler) http.Handler { return outer(inner(next)) }
}
