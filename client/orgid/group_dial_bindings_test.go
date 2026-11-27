// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

// The group-dial client's binding of spec/proverif/e2ee_tcp.pv
// (BIND:org.group, the client's half: client/agent's
// TestServiceModelBindings holds the agent's): a client dialling pg@db
// checks the server's certificate holds group db, and no machine name
// (Peer{Group}); a relay that routes the open to an organisation machine
// outside db is refused (mutant no-group-check). `make spec-bindings`.

import (
	"os"
	"strings"
	"testing"
	"time"
)

var groupDialBindings = map[string]func(t *testing.T){
	"org.group": func(t *testing.T) {
		o := newTestOrg(t, t0)
		o.takeCRL(t, t0)
		at := t0.Add(time.Minute)
		for name, groups := range map[string][]string{"web-1": {"db"}, "web-2": {"web", "db"}} {
			c, _ := o.enrol(t, name, groups...)
			if _, err := o.ver.Check(c, o.iss, Peer{Group: "db"}, at); err != nil {
				t.Errorf("%s (groups %v) for pg@db: %v", name, groups, err)
			}
		}
		// The relay routes pg@db to mal, an organisation machine of group
		// web only.
		mal, _ := o.enrol(t, "mal", "web")
		if _, err := o.ver.Check(mal, o.iss, Peer{Group: "db"}, at); err == nil || !strings.Contains(err.Error(), "not in group db") {
			t.Fatalf("mal (group web) for pg@db: %v, want refused", err)
		}
	},
}

// TestE2EETCPModelBindingsGroupDialClient runs every row; each is a BIND
// id of the model.
func TestE2EETCPModelBindingsGroupDialClient(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/e2ee_tcp.pv")
	if err != nil {
		t.Fatal(err)
	}
	for id, row := range groupDialBindings {
		if !strings.Contains(string(src), "BIND:"+id+" ") {
			t.Errorf("e2ee_tcp.pv declares no BIND:%s", id)
		}
		t.Run(id, row)
	}
}
