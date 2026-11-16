// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"testing"

	"github.com/nfltr/relay/client/nf1"
)

// Listen refuses, offline and typed CodeUsage, what it cannot serve: no
// agent name, a bad service name, both credentials, organisation choices
// without organisation mode, an address with groups, organisation mode
// without groups.
func TestListenUsage(t *testing.T) {
	r := newRelayOrg(t)
	key := func(*Config) {}
	for name, tc := range map[string]struct {
		cfg func(*Config)
		svc string
		o   ListenOptions
	}{
		"no agent":            {func(c *Config) { c.Agent = "" }, "chat", ListenOptions{}},
		"bad service":         {key, "Chat_1", ListenOptions{}},
		"key and cert":        {func(c *Config) { c.ClientCert = r.web.Certificate }, "chat", ListenOptions{}},
		"groups without org":  {key, "chat", ListenOptions{AllowGroups: []string{"db"}}},
		"publish without org": {key, "chat", ListenOptions{Publish: "db"}},
		"direct without org":  {key, "chat", ListenOptions{Direct: DirectOn}},
		"org without groups":  {func(c *Config) { c.Org = r.web }, "chat", ListenOptions{}},
		"no relay":            {func(c *Config) { c.Relay = "" }, "chat", ListenOptions{}},
	} {
		cfg := Config{Relay: "127.0.0.1:1", Agent: "chat", APIKey: "key", Plaintext: true}
		tc.cfg(&cfg)
		l, err := Listen(t.Context(), cfg, tc.svc, tc.o)
		if l != nil {
			_ = l.Close()
		}
		wantCode(t, name, err, CodeUsage, "")
	}
}

// An address served with no credential (no APIKey, no ClientCert) is
// served anonymously: its answer signs a1 beside d1, so it needs direct
// paths (DirectOff: CodeUsage, a udp service too, whose direct paths are
// not served yet); with a credential it is not (nfltr
// docs/decisions/nf1-anon-2026-11-16.md section 1).
func TestListenAnonymous(t *testing.T) {
	addr, _, err := nf1.Mint("relay.example")
	if err != nil {
		t.Fatal(err)
	}
	anon := Config{Relay: "127.0.0.1:1", Agent: "chat", Plaintext: true}
	svc, err := listenService(anon, "chat", ListenOptions{Address: addr, Direct: DirectOn})
	if err != nil || !svc.NF1.Anonymous() {
		t.Fatalf("no credential: %v, anonymous %v", err, svc.NF1 != nil && svc.NF1.Anonymous())
	}
	keyed := anon
	keyed.APIKey = "key"
	if svc, err := listenService(keyed, "chat", ListenOptions{Address: addr, Direct: DirectOn}); err != nil || svc.NF1.Anonymous() {
		t.Fatalf("with a key: %v, anonymous %v", err, svc.NF1.Anonymous())
	}
	l, err := Listen(t.Context(), anon, "chat", ListenOptions{Address: addr})
	if l != nil {
		_ = l.Close()
	}
	wantCode(t, "anonymous, direct off", err, CodeUsage, "")
	p, err := ListenPacket(t.Context(), anon, "chat", ListenOptions{Address: addr})
	if p != nil {
		_ = p.Close()
	}
	wantCode(t, "anonymous datagram service", err, CodeUsage, "")
}
