// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package agentservices is the wire contract of services under one agent
// identity: the declaration an agent sends in its ConnectHTTP request metadata,
// which the relay echoes in its response header when it routes services.
//
// The declaration names services, their kind and, for a service in
// organisation mode, the group it is published under and its direct-path
// setting. Their targets stay on the agent, which dials nothing else (its
// local allow-list). A service's health is a presence label (HealthLabel).
package agentservices

import (
	"encoding/base64"
	"encoding/hex"
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
// TLS the agent terminates with its organisation machine certificate (mutual
// TLS in organisation mode: each side verifies the other's certificate
// against the organisation's root it enrolled with, never anything from the
// relay).
type E2EE string

const (
	// E2EEDefault leaves it to the relay: its policy, else its default.
	E2EEDefault E2EE = ""
	// E2EEOn: every session is end to end encrypted ("tcp+e2ee").
	E2EEOn E2EE = "e2ee"
	// E2EEOff: sessions are plain bytes the relay can read ("tcp+plain").
	E2EEOff E2EE = "plain"
)

// Direct is a service's direct-path setting as its agent declares it.
// Informational: each end's own configuration decides whether a direct
// path is tried, never the relay's word.
type Direct string

const (
	// DirectOff: relayed only (the attribute is absent).
	DirectOff Direct = ""
	// DirectOn: public and LAN candidates ("direct=on").
	DirectOn Direct = "on"
	// DirectPublic: the public address only ("direct=public").
	DirectPublic Direct = "public"
)

// Decl is one declared service. E2EE applies to tcp services only; Group
// (the organisation group the service is published under, dialled as
// <service>@<group>) and Direct to tcp+e2ee services only, the ones in
// organisation mode.
type Decl struct {
	Name   string
	Kind   Kind
	E2EE   E2EE
	Group  string
	Direct Direct
	// NF1 is the rendezvous id of the capability address (nf1...) the
	// service is served under, zero for none: a tcp+e2ee service with no
	// group or direct attribute, each rid once per declaration (";nf1=" and
	// 32 lowercase hex digits; nfltr docs/decisions/nf1-rendezvous-2026-11-13.md).
	NF1 [RIDSize]byte
	// Public: the service also takes anonymous visitors on a public TCP
	// port of the relay, the relay copying its plain bytes (";public", the
	// entry's only attribute, on a tcp+plain service only; nfltr
	// docs/decisions/public-tcp-endpoints-2026-11-13.md). The machine's
	// half of the endpoint's double opt-in: the relay routes a public port
	// only to a live agent whose declaration says so.
	Public bool
}

// RIDSize is the size of a capability address's rendezvous id
// (relay client/capaddr.RIDSize).
const RIDSize = 16

// kindValue is the declaration's kind as written: "http", "tcp",
// "tcp+e2ee" or "tcp+plain".
func (d Decl) kindValue() string {
	if d.E2EE == E2EEDefault {
		return string(d.Kind)
	}
	return string(d.Kind) + "+" + string(d.E2EE)
}

// value is the entry after "name=": the kind, then ";group=G" and
// ";direct=D" when set, in that order.
func (d Decl) value() string {
	v := d.kindValue()
	if d.Group != "" {
		v += ";group=" + d.Group
	}
	if d.Direct != DirectOff {
		v += ";direct=" + string(d.Direct)
	}
	if d.NF1 != ([RIDSize]byte{}) {
		v += ";nf1=" + hex.EncodeToString(d.NF1[:])
	}
	if d.Public {
		v += ";" + publicAttr
	}
	return v
}

// HealthLabelPrefix and HealthDown are a service's health in its agent's
// presence labels: "nfltr.health.<service>" = "down" while the agent finds
// the service's target down; absent, the service is up.
const (
	HealthLabelPrefix = "nfltr.health."
	HealthDown        = "down"
)

// HealthLabel is the presence label key of service name's health.
func HealthLabel(name string) string { return HealthLabelPrefix + name }

// ValidLabel reports whether s is one lowercase DNS label (a-z, 0-9, '-',
// at most 63, no '-' at either end): an organisation group (a machine
// certificate's OU), an agent ref.
func ValidLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
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

// Format is the header value of decls:
// "web=http,db=tcp,pg=tcp+e2ee;group=db;direct=on".
func Format(decls []Decl) string {
	parts := make([]string, len(decls))
	for i, d := range decls {
		parts[i] = d.Name + "=" + d.value()
	}
	return strings.Join(parts, ",")
}

// Parse reads a declaration. Every entry must be name=kind, then at most
// one ";group=G" (G a ValidLabel) and one ";direct=on|public", in that
// order and on a tcp+e2ee service only, with a valid name, a known kind and
// no repeated name; anything else is an error and declares nothing.
func Parse(v string) ([]Decl, error) {
	if v == "" {
		return nil, errors.New("empty service declaration")
	}
	if strings.Count(v, ",") >= MaxServices {
		return nil, fmt.Errorf("more than %d services", MaxServices)
	}
	var out []Decl
	seen := map[string]bool{}
	rids := map[[RIDSize]byte]bool{}
	for entry := range strings.SplitSeq(v, ",") {
		entry, attrs, hasAttrs := strings.Cut(entry, ";")
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
		d := Decl{Name: name, Kind: Kind(kind), E2EE: E2EE(e2ee)}
		if hasAttrs {
			if err := d.parseAttrs(attrs); err != nil {
				return nil, err
			}
		}
		if d.NF1 != ([RIDSize]byte{}) {
			if rids[d.NF1] {
				return nil, fmt.Errorf("service %q: nf1 rendezvous id declared twice", name)
			}
			rids[d.NF1] = true
		}
		out = append(out, d)
	}
	return out, nil
}

// publicAttr is a public service's attribute.
const publicAttr = "public"

// parseAttrs reads the entry's attributes after its first ';' into d.
func (d *Decl) parseAttrs(attrs string) error {
	if d.Kind == TCP && d.E2EE == E2EEOff {
		if attrs != publicAttr {
			return fmt.Errorf("service %q: invalid attributes %q (a tcp+plain service takes only ;public)", d.Name, attrs)
		}
		d.Public = true
		return nil
	}
	if d.Kind != TCP || d.E2EE != E2EEOn {
		return fmt.Errorf("service %q: group, direct and nf1 need a tcp+e2ee service", d.Name)
	}
	if v, ok := strings.CutPrefix(attrs, "nf1="); ok {
		return d.parseNF1(v)
	}
	if v, ok := strings.CutPrefix(attrs, "group="); ok {
		v, rest, more := strings.Cut(v, ";")
		if !ValidLabel(v) {
			return fmt.Errorf("service %q: invalid group %q (a lowercase DNS label)", d.Name, v)
		}
		d.Group = v
		if !more {
			return nil
		}
		attrs = rest
	}
	// The attribute's name is checked too: a bare "on" or "public" is no
	// direct setting.
	if v, ok := strings.CutPrefix(attrs, "direct="); ok && (Direct(v) == DirectOn || Direct(v) == DirectPublic) {
		d.Direct = Direct(v)
		return nil
	}
	return fmt.Errorf("service %q: invalid attributes %q (want ;group=<group> then ;direct=on|public)", d.Name, attrs)
}

// parseNF1 reads ";nf1=" 's value, the entry's only attribute: 32
// lowercase hex digits, not all zero.
func (d *Decl) parseNF1(v string) error {
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != RIDSize || v != strings.ToLower(v) {
		return fmt.Errorf("service %q: invalid nf1 rendezvous id (want %d lowercase hex digits)", d.Name, 2*RIDSize)
	}
	if d.NF1 = [RIDSize]byte(b); d.NF1 == ([RIDSize]byte{}) {
		return fmt.Errorf("service %q: all-zero nf1 rendezvous id", d.Name)
	}
	return nil
}

// FindNF1 returns the declaration of the service served under the
// capability address whose rendezvous id is rid.
func FindNF1(decls []Decl, rid [RIDSize]byte) (Decl, bool) {
	for _, d := range decls {
		if rid != ([RIDSize]byte{}) && d.NF1 == rid {
			return d, true
		}
	}
	return Decl{}, false
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

// RegHeader is the ConnectHTTP request metadata, beside Header, carrying
// the registration proof of each capability address the declaration names
// (relay client/capaddr.RegistrationProof): one value per nf1 rid,
// FormatReg's. The relay checks each against its declaration
// (capaddr.CheckRegistration) and drops it: it is never part of a Decl, a
// record, the echo or a log (nfltr docs/decisions/nf1-risks-2026-11-14.md).
const RegHeader = "x-nfltr-nf1-reg"

// MaxRegProof bounds one registration proof (an Ed25519 one is 126 bytes).
const MaxRegProof = 512

// FormatReg is one RegHeader value: "<rid hex>:<proof, base64 raw URL>".
func FormatReg(rid [RIDSize]byte, proof []byte) string {
	return hex.EncodeToString(rid[:]) + ":" + base64.RawURLEncoding.EncodeToString(proof)
}

// ParseReg reads RegHeader's values: rid -> proof. It refuses a malformed
// value, an all-zero rid, a rid twice, an empty or oversized proof and
// more values than MaxServices. Whether each proof holds is the caller's
// check.
func ParseReg(vals []string) (map[[RIDSize]byte][]byte, error) {
	if len(vals) > MaxServices {
		return nil, fmt.Errorf("%s: more than %d values", RegHeader, MaxServices)
	}
	out := make(map[[RIDSize]byte][]byte, len(vals))
	for _, v := range vals {
		h, p, ok := strings.Cut(v, ":")
		b, err := hex.DecodeString(h)
		if !ok || err != nil || len(b) != RIDSize || h != strings.ToLower(h) || [RIDSize]byte(b) == ([RIDSize]byte{}) {
			return nil, fmt.Errorf("%s: invalid rendezvous id in %q", RegHeader, v)
		}
		rid := [RIDSize]byte(b)
		if _, dup := out[rid]; dup {
			return nil, fmt.Errorf("%s: rendezvous id %s twice", RegHeader, h)
		}
		proof, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil || len(proof) == 0 || len(proof) > MaxRegProof {
			return nil, fmt.Errorf("%s: invalid proof for %s", RegHeader, h)
		}
		out[rid] = proof
	}
	return out, nil
}
