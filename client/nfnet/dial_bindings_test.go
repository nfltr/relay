// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

// The dialling client's bindings of spec/proverif/e2ee_tcp.pv, through
// the Conn's organisation TLS (the client's half: client/agent's
// TestServiceModelBindings holds the agent's, client/orgid's
// TestE2EETCPModelBindingsGroupDialClient the group check itself).
// `make spec-bindings`.

import (
	"os"
	"strings"
	"testing"

	"github.com/nfltr/relay/client/agent"
	"github.com/nfltr/relay/client/orgid"
)

var dialBindings = map[string]func(t *testing.T){
	// A session is bound to the service dialled (mutant
	// client-no-alpn-check): a server of the named machine that does not
	// negotiate it (the relay routed web/pg to web's vault), or negotiates
	// none, is refused.
	"org.service": func(t *testing.T) {
		o := newTestOrg(t)
		web, cli := o.machine(t, "web", "web"), o.machine(t, "cli", "db")
		raw, done := orgServer(t, web, agent.MachineALPN("web", "pg"))
		if err := echo(orgClient(raw, "web/pg", cli, done)); err != nil {
			t.Fatalf("web/pg: %v", err)
		}
		raw, done = orgServer(t, web, agent.MachineALPN("web", "vault"))
		if err := echo(orgClient(raw, "web/pg", cli, done)); err == nil {
			t.Error("web/pg reached web's vault")
		}
		raw, done = orgServer(t, web)
		if err := echo(orgClient(raw, "web/pg", cli, done)); err == nil {
			t.Error("web/pg reached a server that negotiated no service")
		}
	},
	// A group dial (pg@db) reaches any machine of group db that negotiates
	// pg@db, whatever its name, and no machine outside db even when it
	// takes the protocol (mutant group-dial-no-group-check); the refused
	// machine is named for the next pick's exclude (retryGroup).
	"org.group": func(t *testing.T) {
		o := newTestOrg(t)
		ms := map[string]*orgid.Identity{"web-1": o.machine(t, "web-1", "db"), "web-2": o.machine(t, "web-2", "web", "db"), "eve": o.machine(t, "eve", "web")}
		cli := o.machine(t, "cli", "db")
		for _, srv := range []string{"web-1", "web-2"} {
			raw, done := orgServer(t, ms[srv], agent.GroupALPN("pg", "db"))
			if err := echo(orgClient(raw, "pg@db", cli, done)); err != nil {
				t.Errorf("pg@db to %s: %v", srv, err)
			}
		}
		raw, done := orgServer(t, ms["eve"], agent.GroupALPN("pg", "db"))
		c := orgClient(raw, "pg@db", cli, done)
		if err := echo(c); err == nil || c.refusedPeer() != "eve" {
			t.Errorf("pg@db to eve, outside db: %v, refused %q; want refused, naming eve", err, c.refusedPeer())
		}
		raw, done = orgServer(t, ms["web-1"], agent.GroupALPN("vault", "db"))
		if err := echo(orgClient(raw, "pg@db", cli, done)); err == nil {
			t.Error("pg@db reached a server negotiating vault@db")
		}
	},
}

// TestE2EETCPModelBindingsDialClient runs every row; each is a BIND id of
// the model.
func TestE2EETCPModelBindingsDialClient(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/e2ee_tcp.pv")
	if err != nil {
		t.Fatal(err)
	}
	for id, row := range dialBindings {
		if !strings.Contains(string(src), "BIND:"+id+" ") {
			t.Errorf("e2ee_tcp.pv declares no BIND:%s", id)
		}
		t.Run(id, row)
	}
}
