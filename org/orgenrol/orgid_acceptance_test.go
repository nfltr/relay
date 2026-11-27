// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgpki"
)

// What the issuer makes, the relay client's verifier accepts: a machine
// enrolled through the mailboxes by this module (the issuer service, Join,
// the machine directory orgmachine writes) loads with orgid.Load in its
// organisation, and the chain it presents checks as server web-1, as a
// client in group web and as a server of group web; under another name or
// in another group it is refused. As a client it is admitted by the
// root's access policy (lane SA3): signed on the root's machine, posted on
// the drop box (SendPolicy), carried in the issuer's status on the relay's
// copy and taken from there (orgid TakeStatus); a replay of that policy is
// refused. The test across the issuer side (org/) and the verifier side
// (client/orgid) of this repository.
func TestIssuedMachineAcceptedByOrgID(t *testing.T) {
	f := newFleetWith(t, func(f *fleet) { f.copy = true })
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
	if _, err := id.CheckClient(chain, []string{"pg"}, now); err == nil {
		t.Fatal("a client admitted with no access policy")
	}
	sp, err := orgpki.SignPolicy(f.org.rootKey, orgid.Policy{OrgID: f.org.id, Number: 1,
		Rules: []orgid.Rule{{Who: "group:web", Where: "machine:web-1", Service: "pg"}}})
	check(t, err)
	if n, err := SendPolicy(f.ctx, f.relay, f.org.id, sp, hang); err != nil || n != 1 {
		t.Fatalf("the root's policy: %d %v", n, err)
	}
	if n, err := SendPolicy(f.ctx, f.relay, f.org.id, sp, hang); !errors.Is(err, ErrIssuerRefused) || n != 1 {
		t.Fatalf("the policy again: %d %v, want refused at 1", n, err)
	}
	deadline := time.Now().Add(hang)
	for {
		f.relay.mu.Lock()
		msg := f.relay.statuses[f.org.id]
		f.relay.mu.Unlock()
		if msg != nil {
			if _, err := id.TakeStatus(msg, now); err != nil {
				t.Fatal(err)
			}
			if _, err := id.CheckClient(chain, []string{"pg"}, now); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the relay's status copy never carried the policy")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := id.CheckClient(chain, []string{"ssh"}, now); err == nil {
		t.Fatal("a service no rule names admitted")
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
