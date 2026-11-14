// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"testing"
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
