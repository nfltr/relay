// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

// The binding spec/proverif/cap_address.pv's and e2ee_tcp.pv's direct
// datagrams add (BIND:dgram.*), on direct_datagram_test.go's unit.

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/nfltr/relay/client/internal/modelbind"
)

// dgramBindings: BIND:dgram.tag of cap_address.pv and e2ee_tcp.pv, a row
// that changes an honest direct frame's tag and requires a refusal.
var dgramBindings = map[string]func(t *testing.T){
	// The frame of an open flow under the tag of another stream of the
	// connection, one the session is not on (one it left, a stream of
	// no session): never handed to the session's flows.
	"dgram.tag": func(t *testing.T) {
		u := newDGUnit(t)
		id := u.flow(t)
		u.send(t, 1, id, "other tag")
		u.send(t, 0, id, "own tag")
		if !u.reaches("own tag", 5*time.Second) {
			t.Fatal("the honest frame did not reach the target")
		}
		if u.reaches("other tag", 300*time.Millisecond) {
			t.Fatal("a frame under another stream's tag reached the session's flow")
		}
	},
}

// TestDatagramModelBindings runs every row, and fails when the models'
// BIND:dgram ids and the rows differ.
func TestDatagramModelBindings(t *testing.T) {
	rows := slices.Sorted(maps.Keys(dgramBindings))
	for _, m := range []string{"cap_address.pv", "e2ee_tcp.pv"} {
		src, err := os.ReadFile("../../spec/proverif/" + m)
		if err != nil {
			t.Fatal(err)
		}
		if err := modelbind.Check(src, regexp.MustCompile(`BIND:(dgram\.[a-z0-9.]+)`), rows); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	for _, id := range rows {
		t.Run(id, dgramBindings[id])
	}
}
