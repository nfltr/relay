// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package nfnet dials and serves sessions by identity through a relay (nfltr
// docs/decisions/p2p-sdk-2026-11-14.md). This first slice holds the target
// grammar (ParseTarget) and the typed errors of the connect sidecar's exit
// table (Error, Code, CodeOf); Dial and Listen follow.
package nfnet

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// TargetKind is which of the grammar's forms a Target is.
type TargetKind int

const (
	// AgentTarget is <agent>/<service> (this machine's agent) or
	// <ref>/<service> (an agent by ref).
	AgentTarget TargetKind = iota + 1
	// MachineTarget is <machine>.<agent>/<service>.
	MachineTarget
	// GroupTarget is <service>@<group>: one instance of the service an
	// organisation group publishes.
	GroupTarget
	// AddressTarget is a capability address nf1...
	AddressTarget
)

// Target is a parsed target (nfltr docs/decisions/cli-cat-2026-11-12.md
// section 2). Machine is set for MachineTarget (Agent then the part after
// its first '.'), Group for GroupTarget, Address for AddressTarget.
type Target struct {
	Kind    TargetKind
	Machine string
	Agent   string
	Service string
	Group   string
	Address capaddr.Address
}

// usageForms names the four forms in a usage error.
const usageForms = "want one target: <agent>/<service>, <machine>.<agent>/<service>, <ref>/<service>, <service>@<group> or an nf1... address"

// ParseTarget reads a target offline (no DNS): a text starting with nf1
// with no / or @ is a capability address; one with @ is <service>@<group>;
// one with / is <agent>/<service> (<machine>.<agent>/<service> when the
// agent holds a '.'). Anything else is an *Error CodeUsage, and so is a
// text that holds an address (a token of nf1 and 40 or more letters and
// digits, any case) in
// another form: an address names one service, and its secret must not
// reach a relay as an agent's name. So neither an error nor String ever
// holds an address's text.
func ParseTarget(s string) (Target, error) {
	if strings.HasPrefix(s, capaddr.Prefix) && !strings.ContainsAny(s, "/@") {
		a, err := capaddr.Parse(s)
		if err != nil {
			return Target{}, &Error{Code: CodeUsage, Message: "invalid capability address: " + err.Error(), Err: err}
		}
		return Target{Kind: AddressTarget, Address: a}, nil
	}
	if !strings.ContainsAny(s, "/@") {
		return Target{}, usage(usageForms)
	}
	if holdsAddress(s) {
		return Target{}, usage("a capability address names one service: give it alone, with no /<service> or @<group>")
	}
	if svc, group, ok := strings.Cut(s, "@"); ok {
		switch {
		case !agentservices.ValidName(svc):
			return Target{}, usage(fmt.Sprintf("invalid service %q in %q (lowercase letters, digits and dashes, starting with a letter)", svc, s))
		case !agentservices.ValidLabel(group):
			return Target{}, usage(fmt.Sprintf("invalid group %q in %q (an organisation group: lowercase letters, digits and dashes)", group, s))
		}
		return Target{Kind: GroupTarget, Service: svc, Group: group}, nil
	}
	agent, svc, _ := strings.Cut(s, "/")
	switch {
	case !agentservices.ValidName(svc):
		return Target{}, usage(fmt.Sprintf("invalid service %q in %q (lowercase letters, digits and dashes, starting with a letter)", svc, s))
	case !validAgentName(agent):
		return Target{}, usage(fmt.Sprintf("invalid agent name %q (use alphanumeric, dash, underscore)", agent))
	}
	if m, a, ok := strings.Cut(agent, "."); ok {
		return Target{Kind: MachineTarget, Machine: m, Agent: a, Service: svc}, nil
	}
	return Target{Kind: AgentTarget, Agent: agent, Service: svc}, nil
}

// String is the target's text (ParseTarget reads it back); for an
// AddressTarget "nf1:<rid prefix>@<relay>", never the address's text.
func (t Target) String() string {
	switch t.Kind {
	case AddressTarget:
		return "nf1:" + hex.EncodeToString(t.Address.RID[:4]) + "@" + t.Address.Relay
	case GroupTarget:
		return t.Service + "@" + t.Group
	case MachineTarget:
		return t.Machine + "." + t.Agent + "/" + t.Service
	case AgentTarget:
		return t.Agent + "/" + t.Service
	}
	return ""
}

func usage(msg string) *Error { return &Error{Code: CodeUsage, Message: msg} }

// validAgentName: 1-255 bytes of letters, digits, '-', '_', '.', ':' (the
// relay's URL path and header safe set; nfltr cliutil.IsValidAgentName).
func validAgentName(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' && c != ':' {
			return false
		}
	}
	return true
}

// tokens are s's maximal runs of letters and digits, the alphabet of an
// address's text (capaddr.Prefix and base32, in either case: a decoder
// may not care).
func tokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
}

// minAddress is far below the shortest address text (143 characters, a
// one-byte relay): a token of nf1 and this many characters is taken for
// an address, maybe mistyped or cut short.
const minAddress = 40

func looksLikeAddress(tok string) bool {
	return len(tok) >= minAddress && strings.EqualFold(tok[:len(capaddr.Prefix)], capaddr.Prefix)
}

// holdsAddress: s embeds what may be an address's text.
func holdsAddress(s string) bool {
	return slices.ContainsFunc(tokens(s), looksLikeAddress)
}
