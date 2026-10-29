// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package agentservices is the wire contract of services under one agent
// identity: the declaration an agent sends in its ConnectHTTP request metadata,
// which the relay echoes in its response header when it routes services.
//
// The declaration names services and their kind only. Their targets stay
// on the agent, which dials nothing else (its local allow-list).
package agentservices

import (
	"errors"
	"fmt"
	"strings"
)

// Header is the ConnectHTTP request metadata that declares an agent's
// services and the response header in which a relay accepts them (the same
// canonical value). An older relay sends no such header.
const Header = "x-nfltr-services"

// ModesHeader is the ConnectHTTP request metadata (value "1") in which an
// agent says it reads each tcp service's E2EE mode in the relay's echo and
// serves it so: the relay then echoes every tcp service resolved
// ("+e2ee", "+plain"). An agent without it (nfltr before v2.1.6) cannot
// terminate E2EE on a tcp service: the relay echoes its declaration as
// sent and serves its tcp services plain, or refuses them where its
// policy requires E2EE.
const ModesHeader = "x-nfltr-services-modes"

// RequestHeader is the HTTP request header in which the relay names the
// service of a request it delivers through a service's share. The relay
// sets it, or removes a client's, on every share request.
const RequestHeader = "X-Nfltr-Service"

// MaxServices bounds one agent's declaration.
const MaxServices = 64

// Kind is what a service serves.
type Kind string

const (
	// HTTP services take share URLs: inspectable requests carry the
	// service (RequestHeader), E2EE sessions name it in the open frame.
	HTTP Kind = "http"
	// TCP services take the owner's tcp-connect sessions, which name the
	// service in place of a port.
	TCP Kind = "tcp"
)

// E2EE is a tcp service's end-to-end encryption: whether its sessions are
// TLS the agent terminates with its E2EE certificate (the client verifies
// the certificate against a pin it got from the agent, never the relay).
type E2EE string

const (
	// E2EEDefault leaves it to the relay: its policy, else its default.
	E2EEDefault E2EE = ""
	// E2EEOn: every session is end to end encrypted ("tcp+e2ee").
	E2EEOn E2EE = "e2ee"
	// E2EEOff: sessions are plain bytes the relay can read ("tcp+plain").
	E2EEOff E2EE = "plain"
)

// Decl is one declared service. E2EE applies to tcp services only.
type Decl struct {
	Name string
	Kind Kind
	E2EE E2EE
}

// kindValue is the declaration's kind as written: "http", "tcp",
// "tcp+e2ee" or "tcp+plain".
func (d Decl) kindValue() string {
	if d.E2EE == E2EEDefault {
		return string(d.Kind)
	}
	return string(d.Kind) + "+" + string(d.E2EE)
}

// ValidName reports whether name is a service name: a DNS label that starts
// with a letter, so it never reads as a port number.
func ValidName(name string) bool {
	if name == "" || len(name) > 63 || name[0] < 'a' || name[0] > 'z' || name[len(name)-1] == '-' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// Format is the header value of decls: "web=http,db=tcp,vault=tcp+e2ee".
func Format(decls []Decl) string {
	parts := make([]string, len(decls))
	for i, d := range decls {
		parts[i] = d.Name + "=" + d.kindValue()
	}
	return strings.Join(parts, ",")
}

// Parse reads a declaration. Every entry must be name=kind with a valid
// name, a known kind and no repeated name; anything else is an error and
// declares nothing.
func Parse(v string) ([]Decl, error) {
	if v == "" {
		return nil, errors.New("empty service declaration")
	}
	if strings.Count(v, ",") >= MaxServices {
		return nil, fmt.Errorf("more than %d services", MaxServices)
	}
	var out []Decl
	seen := map[string]bool{}
	for entry := range strings.SplitSeq(v, ",") {
		name, kind, ok := strings.Cut(entry, "=")
		if !ok || !ValidName(name) {
			return nil, fmt.Errorf("invalid service entry %q (want name=kind, name a DNS label starting with a letter)", entry)
		}
		kind, e2ee, plus := strings.Cut(kind, "+")
		if k := Kind(kind); k != HTTP && k != TCP {
			return nil, fmt.Errorf("service %q: unknown kind %q (want http or tcp)", name, kind)
		}
		if e := E2EE(e2ee); plus && (Kind(kind) != TCP || (e != E2EEOn && e != E2EEOff)) {
			return nil, fmt.Errorf("service %q: unknown kind %q (want tcp+e2ee or tcp+plain)", name, kind+"+"+e2ee)
		}
		if seen[name] {
			return nil, fmt.Errorf("service %q declared twice", name)
		}
		seen[name] = true
		out = append(out, Decl{Name: name, Kind: Kind(kind), E2EE: E2EE(e2ee)})
	}
	return out, nil
}

// Find returns the declaration of the service named name.
func Find(decls []Decl, name string) (Decl, bool) {
	for _, d := range decls {
		if d.Name == name {
			return d, true
		}
	}
	return Decl{}, false
}

// Lookup returns the kind of the service named name, "" when none is.
func Lookup(decls []Decl, name string) Kind {
	for _, d := range decls {
		if d.Name == name {
			return d.Kind
		}
	}
	return ""
}
