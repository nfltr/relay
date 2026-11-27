// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// nfltrCat is nfltr's parse of a cat verb's one target at nfltr 4134b83ad,
// copied verbatim (connectcli.CatTarget, transportcli.ParseNF1, then
// transportcli.ParseTarget, cliutil.IsValidAgentName and IsValidPortStr):
// the reference ParseTarget must match until nfltr calls ParseTarget
// (lane P2PSDK5). agent is the relay's agent name ("pg@db" for a group).
func nfltrCat(target string) (agentName, remote string, isNF1 bool, err error) {
	args := []string{target}
	if len(args) != 1 || (!strings.ContainsAny(args[0], "/@") && !strings.HasPrefix(args[0], "nf1")) {
		return "", "", false, errors.New("want one target: <agent>/<service>, <machine>.<agent>/<service>, <ref>/<service>, <service>@<group> or an nf1... address")
	}
	if strings.HasPrefix(target, capaddr.Prefix) && !strings.ContainsAny(target, "/@") {
		_, err = capaddr.Parse(target)
		return "", "", true, err
	}
	agentName = args[0]
	if svc, group, ok := strings.Cut(agentName, "@"); ok {
		switch {
		case !agentservices.ValidName(svc):
			return "", "", false, fmt.Errorf("invalid service %q in %q (lowercase letters, digits and dashes, starting with a letter)", svc, agentName)
		case !agentservices.ValidLabel(group):
			return "", "", false, fmt.Errorf("invalid group %q in %q (an organisation group: lowercase letters, digits and dashes)", group, agentName)
		case len(args) > 1:
			return "", "", false, fmt.Errorf("%s names a service: give no port", agentName)
		}
		return agentName, svc, false, nil
	}
	if a, svc, ok := strings.Cut(agentName, "/"); ok {
		switch {
		case !agentservices.ValidName(svc):
			return "", "", false, fmt.Errorf("invalid service %q in %q (lowercase letters, digits and dashes, starting with a letter)", svc, agentName)
		case len(args) > 1:
			return "", "", false, fmt.Errorf("%s names a service: give no port", agentName)
		}
		agentName, remote = a, svc
	} else {
		return "", "", false, errors.New("agent name and port required") // len(args) < 2
	}
	if !nfltrValidAgentName(agentName) {
		return "", "", false, fmt.Errorf("invalid agent name %q (use alphanumeric, dash, underscore)", agentName)
	}
	return agentName, remote, false, nil
}

func nfltrValidAgentName(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' && c != ':' {
			return false
		}
	}
	return true
}

// wire is t as nfltr's parse names it: the relay's agent name and the
// service.
func (t Target) wire() (agent, remote string) {
	switch t.Kind {
	case GroupTarget:
		return t.Service + "@" + t.Group, t.Service
	case MachineTarget:
		return t.Machine + "." + t.Agent, t.Service
	}
	return t.Agent, t.Service
}

// checkParity is the differential: ParseTarget accepts what nfltr's parse
// accepts, with the same parts, but for one deliberate refusal (a text
// holding an address in another form, which nfltr would send to the relay
// as an agent's name); every refusal is an *Error CodeUsage; an accepted
// target reads back from String.
func checkParity(t *testing.T, s string) {
	t.Helper()
	got, err := ParseTarget(s)
	agent, remote, isNF1, rerr := nfltrCat(s)
	switch {
	case err != nil && CodeOf(err) != CodeUsage:
		t.Fatalf("ParseTarget(%q): %v is not CodeUsage (%d)", s, err, CodeOf(err))
	case err != nil && rerr == nil && !holdsAddress(s):
		t.Fatalf("ParseTarget(%q) refused what nfltr accepts: %v", s, err)
	case err == nil && rerr != nil:
		t.Fatalf("ParseTarget(%q) = %+v, nfltr refuses: %v", s, got, rerr)
	case err != nil:
		return
	case isNF1 != (got.Kind == AddressTarget):
		t.Fatalf("ParseTarget(%q) kind %d, nfltr nf1=%v", s, got.Kind, isNF1)
	case got.Kind == AddressTarget:
		if got.Address.String() != s {
			t.Fatalf("ParseTarget(%q) address %q", s, got.Address)
		}
		return
	}
	if a, r := got.wire(); a != agent || r != remote {
		t.Fatalf("ParseTarget(%q) = %q %q, nfltr %q %q", s, a, r, agent, remote)
	}
	if back, err := ParseTarget(got.String()); err != nil || back != got {
		t.Fatalf("ParseTarget(%q).String() = %q reads back %+v, %v", s, got.String(), back, err)
	}
}

func mintAddress(t testing.TB, relay string) string {
	l, _, err := nf1.Mint(relay)
	if err != nil {
		t.Fatal(err)
	}
	return l.Address().String()
}

// typo changes an address's last character (nfltr connectcli's typo).
func typo(addr string) string {
	last := "a"
	if strings.HasSuffix(addr, last) {
		last = "b"
	}
	return addr[:len(addr)-1] + last
}

// TestParseTarget: the four forms, each case of nfltr's parser tests that
// a cat target can take (TestCatTarget, TestTCPConnectTarget,
// TestNF1Target), with nfltr's own parse as the reference.
func TestParseTarget(t *testing.T) {
	addr := mintAddress(t, "relay.test:8443")
	for _, tc := range []struct {
		s    string
		want Target // zero: refused
	}{
		// connectcli TestCatTarget
		{"home/db", Target{Kind: AgentTarget, Agent: "home", Service: "db"}},
		{"web-1.db/pg", Target{Kind: MachineTarget, Machine: "web-1", Agent: "db", Service: "pg"}},
		{"pg@db", Target{Kind: GroupTarget, Service: "pg", Group: "db"}},
		{"", Target{}},
		{"home", Target{}},
		// transportcli TestTCPConnectTarget (one-argument cases; the
		// <agent> <port> form is not a cat target)
		{"alice.home/web-2", Target{Kind: MachineTarget, Machine: "alice", Agent: "home", Service: "web-2"}},
		{"my-db", Target{}},
		{"home/5432", Target{}},
		{"home/", Target{}},
		{"/db", Target{}},
		{"home/db/x", Target{}},
		{"home/DB", Target{}},
		{"ho me/db", Target{}},
		{"home/../db", Target{}},
		{"pg@", Target{}},
		{"@db", Target{}},
		{"PG@db", Target{}},
		{"pg@DB", Target{}},
		{"pg@db/x", Target{}},
		{"pg@d_b", Target{}},
		// refs and agent names nfltr accepts
		{"m7f3a91c2-db/pg", Target{Kind: AgentTarget, Agent: "m7f3a91c2-db", Service: "pg"}},
		{"Home_1:x/db", Target{Kind: AgentTarget, Agent: "Home_1:x", Service: "db"}},
		{"a.b.c/db", Target{Kind: MachineTarget, Machine: "a", Agent: "b.c", Service: "db"}},
		{"nf1-box/db", Target{Kind: AgentTarget, Agent: "nf1-box", Service: "db"}},
		{"nf1", Target{}},
		{"nf1x", Target{}},
		// connectcli TestNF1Target
		{typo(addr), Target{}},
		// an address names one service (the one divergence from nfltr,
		// which reads these as an agent named by the address's text)
		{addr + "/db", Target{}},
		{"x." + addr + "/db", Target{}},
		{typo(addr) + "/db", Target{}},
		{"db@" + addr, Target{}},
	} {
		got, err := ParseTarget(tc.s)
		if tc.want == (Target{}) {
			if err == nil {
				t.Errorf("ParseTarget(%.24q) = %+v, want a usage error", tc.s, got)
			}
		} else if err != nil || got != tc.want {
			t.Errorf("ParseTarget(%q) = %+v, %v; want %+v", tc.s, got, err, tc.want)
		}
		checkParity(t, tc.s)
	}
	got, err := ParseTarget(addr)
	if err != nil || got.Kind != AddressTarget || got.Address.String() != addr || got.Address.Relay != "relay.test:8443" {
		t.Fatalf("ParseTarget(nf1...) = %+v, %v", got, err)
	}
	checkParity(t, addr)
}

// TestTargetNeverPrintsTheSecret: an address's text is in neither
// String nor any error, in any form it is given in.
func TestTargetNeverPrintsTheSecret(t *testing.T) {
	addr := mintAddress(t, "relay.test")
	secret := addr[len(capaddr.Prefix)+20:] // past the relay's bytes
	for _, s := range []string{
		addr, typo(addr), addr[:len(addr)-5], addr + "/db", addr + "@db", "db@" + addr,
		"x." + addr + "/db", addr + "/DB", "ho me/" + addr, addr + "x", strings.ToUpper(addr) + "/db",
	} {
		got, err := ParseTarget(s)
		if err == nil && strings.Contains(strings.ToLower(got.String()), secret) {
			t.Errorf("String of %.24q... holds the address: %q", s, got.String())
		}
		if err != nil && strings.Contains(strings.ToLower(err.Error()), secret) {
			t.Errorf("error of %.24q... holds the address: %q", s, err.Error())
		}
	}
	got, _ := ParseTarget(addr)
	if s := got.String(); !strings.HasPrefix(s, "nf1:") || !strings.HasSuffix(s, "@relay.test") || len(s) != len("nf1:01234567@relay.test") {
		t.Fatalf("String = %q, want nf1:<rid prefix>@relay.test", s)
	}
}

// TestParseTargetIsOffline: a pasted address is read without a lookup
// (its relay is a name nobody resolves).
func TestParseTargetIsOffline(t *testing.T) {
	addr := mintAddress(t, "relay.invalid")
	if got, err := ParseTarget(addr); err != nil || got.Address.Relay != "relay.invalid" {
		t.Fatalf("ParseTarget = %+v, %v", got, err)
	}
}
