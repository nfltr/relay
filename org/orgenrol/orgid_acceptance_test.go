// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"crypto/x509"
	"testing"

	"github.com/nfltr/relay/client/orgid"
)

// What the issuer makes, the relay client's verifier accepts: a machine
// enrolled through the mailboxes by this module (the issuer service, Join,
// the machine directory orgmachine writes) loads with orgid.Load in its
// organisation, and the chain it presents checks as server web-1, as a
// client in group web and as a server of group web; under another name or
// in another group it is refused. The test across the issuer side (org/)
// and the verifier side (client/orgid) of this repository.
func TestIssuedMachineAcceptedByOrgID(t *testing.T) {
	f := newFleet(t)
	id, err := orgid.Load(f.dir)
	check(t, err)
	if id.OrgID() != f.org.id {
		t.Fatalf("organisation %q, want %q", id.OrgID(), f.org.id)
	}
	tc, err := id.Certificate()
	check(t, err)
	var chain []*x509.Certificate
	for _, der := range tc.Certificate {
		c, err := x509.ParseCertificate(der)
		check(t, err)
		chain = append(chain, c)
	}
	now := f.clk.Now()
	if _, err := id.CheckServer(chain, "web-1", now); err != nil {
		t.Fatalf("server web-1: %v", err)
	}
	if _, err := id.CheckClient(chain, []string{"web"}, now); err != nil {
		t.Fatalf("client in group web: %v", err)
	}
	if _, err := id.CheckServerGroup(chain, "web", now); err != nil {
		t.Fatalf("server of group web: %v", err)
	}
	if _, err := id.CheckServer(chain, "web-2", now); err == nil {
		t.Fatal("web-1's chain accepted as web-2")
	}
	if _, err := id.CheckServerGroup(chain, "db", now); err == nil {
		t.Fatal("web-1 (group web) accepted as a server of group db")
	}
}
