// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"testing"

	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// Listen refuses, offline and typed CodeUsage, what it cannot serve: no
// agent name, a bad service name, both credentials, organisation choices
// without organisation mode. (Organisation mode names no groups: who may
// connect is the organisation's access rules.)
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
		"publish without org": {key, "chat", ListenOptions{Publish: "db"}},
		"direct without org":  {key, "chat", ListenOptions{Direct: DirectOn}},
		"no relay":            {func(c *Config) { c.Relay = "" }, "chat", ListenOptions{}},
	} {
		cfg := Config{Relay: "127.0.0.1:1", Agent: "chat", Token: "key", Plaintext: true}
		tc.cfg(&cfg)
		l, err := Listen(t.Context(), cfg, tc.svc, tc.o)
		if l != nil {
			_ = l.Close()
		}
		wantCode(t, name, err, CodeUsage, "")
	}
}

// An address served with no credential (no Token, no ClientCert) is
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
	keyed.Token = "key"
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

// RelayCap sets an address's daily relay cap as the agent's label the
// relay reads (relay-core nf1cap.LabelPrefix + the service's target; nfltr
// docs/decisions/nf1-relay-cap-2026-11-25.md): for an Address only, not
// negative.
func TestListenRelayCap(t *testing.T) {
	addr, _, err := nf1.Mint("relay.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Relay: "127.0.0.1:1", Agent: "chat", Token: "key", Plaintext: true}
	one, minus := int64(1<<30), int64(-1)
	for name, o := range map[string]ListenOptions{
		"no address": {RelayCap: &one},
		"negative":   {Address: addr, RelayCap: &minus},
	} {
		if _, err := listenService(cfg, "chat", o); err == nil {
			t.Errorf("%s: no usage error", name)
		}
	}
	svc, err := listenService(cfg, "chat", ListenOptions{Address: addr, RelayCap: &one})
	if err != nil {
		t.Fatal(err)
	}
	if got := relayCapLabels(ListenOptions{Address: addr, RelayCap: &one}, svc); len(got) != 1 || got["nfltr.nf1.relay_cap.chat"] != "1073741824" {
		t.Fatalf("labels %v", got)
	}
	svc.Kind = agentservices.UDP
	if got := relayCapLabels(ListenOptions{Address: addr, RelayCap: &one}, svc); got["nfltr.nf1.relay_cap.chat+udp"] != "1073741824" {
		t.Fatalf("udp labels %v", got)
	}
	if got := relayCapLabels(ListenOptions{Address: addr}, svc); got != nil {
		t.Fatalf("no cap: labels %v", got)
	}
}
