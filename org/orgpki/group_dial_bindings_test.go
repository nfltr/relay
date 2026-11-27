// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The group-dial client's binding of relay spec/proverif/e2ee_tcp.pv
// (BIND:org.group, the client's half: the relay's TestServiceModelBindings
// holds the agent's): a client dialling pg@db checks the server's
// certificate holds group db, and no machine name (Peer{Group}); a relay
// that routes the open to an organisation machine outside db is refused
// (mutant group-dial-no-group-check). `make spec-bindings`.

import (
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

func TestE2EETCPModelBindingsGroupDialClient(t *testing.T) {
	o := newOrg(t)
	o.takeCRL(t, t0)
	at := t0.Add(time.Minute)
	for name, groups := range map[string][]string{"web-1": {"db"}, "web-2": {"web", "db"}} {
		c, _ := o.enrol(t, name, groups...)
		if _, err := o.ver.Check(c, o.iss.Cert(), orgid.Peer{Group: "db"}, at); err != nil {
			t.Errorf("%s (groups %v) for pg@db: %v", name, groups, err)
		}
	}
	// org.group: the relay routes pg@db to mal, an organisation machine
	// of group web only.
	mal, _ := o.enrol(t, "mal", "web")
	if _, err := o.ver.Check(mal, o.iss.Cert(), orgid.Peer{Group: "db"}, at); err == nil || !strings.Contains(err.Error(), "not in group db") {
		t.Fatalf("mal (group web) for pg@db: %v, want refused", err)
	}
}
