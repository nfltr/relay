// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"

	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
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
	// E2EE of a TCP service: On, its sessions are TLS the agent terminates
	// with its E2EE certificate (a plain session is refused); Off, plain
	// bytes only; Default, either, as the relay's policy resolves it.
	E2EE agentservices.E2EE
}

// ServiceTable is the services an agent serves under its identity: the
// only targets its ConnectTCP sessions reach. A session that names no
// service of the table, a service of the wrong kind or a raw address is
// refused (closed, logged, counted), never dialled: the agent is no open
// forwarder. Build it before the tunnel runs; it is read-only after.
type ServiceTable struct {
	byName  map[string]*tableService
	decls   []agentservices.Decl
	refused atomic.Uint64
}

type tableService struct {
	kind    agentservices.Kind
	e2ee    agentservices.E2EE
	network string   // TCP: "tcp" or "unix"
	addr    string   // TCP: the address dialled
	backend string   // HTTP: the backend URL
	shares  []string // share codes whose policy wrap enforces
	wrap    func(http.Handler) http.Handler
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
		e := &tableService{kind: s.Kind, e2ee: s.E2EE}
		if s.E2EE != agentservices.E2EEDefault && (s.Kind != agentservices.TCP || (s.E2EE != agentservices.E2EEOn && s.E2EE != agentservices.E2EEOff)) {
			return nil, fmt.Errorf("service %q: e2ee %q (want %q or %q on a tcp service)", s.Name, s.E2EE, agentservices.E2EEOn, agentservices.E2EEOff)
		}
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
		t.decls = append(t.decls, agentservices.Decl{Name: s.Name, Kind: s.Kind, E2EE: s.E2EE})
	}
	return t, nil
}

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
	case e2ee && !terminatesE2EE:
		return refuse(relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE, "the agent does not terminate end-to-end TLS")
	case e2ee && e.kind == agentservices.TCP && !connect:
		return refuse(relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE, "an end-to-end encrypted share session needs an http service")
	case e2ee && e.e2ee == agentservices.E2EEOff:
		return refuse(relayv1.ErrorReason_ERROR_REASON_E2EE_UNAVAILABLE, "the service is not end-to-end encrypted")
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
