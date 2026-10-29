// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ErrEmptyDestinationPolicy is returned for an empty allow-list: a forwarding
// agent reaches nothing until the operator names destinations or "all".
var ErrEmptyDestinationPolicy = errors.New(`wg: no destinations allowed; list CIDRs or host[:port] entries, or "all" to forward everywhere but the exit's own localhost`)

// DestinationPolicy is the set of destinations a forwarding agent
// (`nfltr wg serve --allow`) may reach. The zero value allows nothing.
//
// The exit's own loopback and unspecified addresses (127.0.0.0/8, ::1,
// 0.0.0.0, ::) are never reached through "all" or a wider CIDR such as
// 0.0.0.0/0: services bound to the exit's localhost are reachable only
// through an entry that names loopback itself, e.g. 127.0.0.1:5432 or
// localhost:5432.
type DestinationPolicy struct {
	all   bool
	rules []destinationRule
}

type destinationRule struct {
	prefix netip.Prefix
	port   uint16 // 0 = any port
}

// HostLookup resolves a hostname to addresses (net.DefaultResolver.LookupNetIP
// in production).
type HostLookup func(host string) ([]netip.Addr, error)

// ParseDestinationPolicy parses allow-list entries. Each entry is "all", a
// CIDR, an IP or a hostname, optionally followed by ":port" (IPv6 with a
// port as "[addr]:port"). Hostnames are resolved once, here.
func ParseDestinationPolicy(entries []string, lookup HostLookup) (DestinationPolicy, error) {
	var p DestinationPolicy
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, "all") {
			p.all = true
			continue
		}
		rules, err := parseDestinationEntry(entry, lookup)
		if err != nil {
			return DestinationPolicy{}, fmt.Errorf("wg: allow entry %q: %w", entry, err)
		}
		p.rules = append(p.rules, rules...)
	}
	if !p.all && len(p.rules) == 0 {
		return DestinationPolicy{}, ErrEmptyDestinationPolicy
	}
	return p, nil
}

func parseDestinationEntry(entry string, lookup HostLookup) ([]destinationRule, error) {
	host, port := entry, uint16(0)
	if _, err := netip.ParseAddr(entry); err != nil { // a bare IPv6 address has colons but no port
		if h, portText, splitErr := net.SplitHostPort(entry); splitErr == nil {
			n, err := strconv.ParseUint(portText, 10, 16)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("invalid port %q", portText)
			}
			host, port = h, uint16(n)
		}
	}
	if prefix, err := netip.ParsePrefix(host); err == nil {
		return []destinationRule{{prefix: prefix.Masked(), port: port}}, nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []destinationRule{{prefix: netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), port: port}}, nil
	}
	if lookup == nil || strings.ContainsAny(host, "/[]") {
		return nil, errors.New("not a CIDR, IP or hostname")
	}
	addrs, err := lookup(host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	rules := make([]destinationRule, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		rules = append(rules, destinationRule{prefix: netip.PrefixFrom(addr, addr.BitLen()), port: port})
	}
	return rules, nil
}

// Allows reports whether addr:port is inside the policy.
func (p DestinationPolicy) Allows(addr netip.Addr, port uint16) bool {
	addr = addr.Unmap()
	local := addr.IsLoopback() || addr.IsUnspecified()
	for _, r := range p.rules {
		if r.prefix.Contains(addr) && (r.port == 0 || r.port == port) && (!local || r.namesExitLocal()) {
			return true
		}
	}
	return p.all && !local
}

// namesExitLocal reports whether the rule itself names a loopback range or
// the unspecified address, rather than containing one as part of a wider
// range.
func (r destinationRule) namesExitLocal() bool {
	return r.prefix.Addr().IsLoopback() || (r.prefix.IsSingleIP() && r.prefix.Addr().IsUnspecified())
}

// String renders the policy for logs.
func (p DestinationPolicy) String() string {
	if p.all && len(p.rules) == 0 {
		return "all"
	}
	if len(p.rules) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(p.rules))
	for _, r := range p.rules {
		if r.port == 0 {
			parts = append(parts, r.prefix.String())
			continue
		}
		parts = append(parts, net.JoinHostPort(r.prefix.String(), strconv.Itoa(int(r.port))))
	}
	if p.all {
		parts = append(parts, "all")
	}
	return strings.Join(parts, ", ")
}
