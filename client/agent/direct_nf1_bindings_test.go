// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// The binding spec/proverif/cap_address.pv's direct phase adds
// (BIND:nf1direct.*; the tokens are the organisation's rows,
// TestDirectModelBindings), on direct_nf1_test.go's rig.

import (
	"context"
	"fmt"
	"maps"
	"net"
	"os"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/internal/modelbind"
	"github.com/nfltr/relay/client/nf1"
)

// nf1DirectBindings: each BIND:nf1direct.* of cap_address.pv, a row that
// changes what a relay can change of an honest attach and requires a
// refusal.
var nf1DirectBindings = map[string]func(t *testing.T){
	// The relay points the agent's candidate at another holder, which
	// answers the punch under another key (for the session's own server
	// name): the client refuses it and stays relayed, bytes intact.
	"nf1direct.pin": func(t *testing.T) {
		r := newNF1Rig(t, DirectPublic) // the reflexive candidate only: the rogue holds it
		other, _, err := nf1.Mint("relay.example")
		if err != nil {
			t.Fatal(err)
		}
		rogue, err := newDirectServer(nil, nil, map[string]DirectMode{"blob": DirectOn})
		if err != nil {
			t.Fatal(err)
		}
		rogue.ep.loopback = true
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = rogue.node.Drain(ctx)
			_ = rogue.ep.Close()
		})
		r.l.targets.qad = tunnelQAD(lyingQAD(t, fmt.Sprintf("127.0.0.1:%d", rogue.ep.pc.LocalAddr().(*net.UDPAddr).Port)))
		ds, tc := r.handshake(t)
		key, err := sessionKey(tc.ConnectionState())
		if err != nil {
			t.Fatal(err)
		}
		rogue.registerSession(&directSession{c: ds.c, key: key, nf1: other, sni: nf1SNI(key)}) // it knows the name: the worst case
		events := r.run(t, ds, tc)
		if e := waitPath(t, events, PathRelayed); e.Reason != ReasonRefusedCert {
			t.Fatalf("reason %q, want %s", e.Reason, ReasonRefusedCert)
		}
		echo(t, tc, 64<<10, func() {})
	},
}

// TestNF1DirectModelBindings runs every row, and fails when the model's
// BIND:nf1direct ids and the rows differ.
func TestNF1DirectModelBindings(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/cap_address.pv")
	if err != nil {
		t.Fatal(err)
	}
	rows := slices.Sorted(maps.Keys(nf1DirectBindings))
	if err := modelbind.Check(src, regexp.MustCompile(`BIND:(nf1direct\.[a-z0-9.]+)`), rows); err != nil {
		t.Fatalf("cap_address.pv: %v", err)
	}
	for _, id := range rows {
		t.Run(id, nf1DirectBindings[id])
	}
}
