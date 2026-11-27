// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nfltr/relay/org/orgissuer"
)

var errMailboxDown = errors.New("mailbox: 502 bad gateway")

// copyRelay is the test relay with its copy of each organisation's CRL
// (relay-server /api/v1/org-crl/<org id>): the issuer puts it
// (CRLCopyWriter), members read it (CRLCopy). A fleet without it has the
// mailbox alone (the push and backstop tests).
type copyRelay struct{ *relay }

func (r copyRelay) PutOrgCRL(_ context.Context, orgID string, msg []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.copies == nil {
		r.copies = map[string][]byte{}
	}
	r.copies[orgID] = slices.Clone(msg)
	return nil
}

func (r copyRelay) OrgCRL(_ context.Context, orgID string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.copies[orgID], nil
}

// With the mailbox service down, a revoke reaches the machine through the
// relay's copy: the issuer puts it although the mailbox refuses the
// publish, the keeper reads it (CrlCarriers.tla CurrentWithoutMailbox;
// mutant mailbox-only, the code before 2026-11-20: the 2026-11-19 mailbox
// outage lapsed every member's CRL after an hour).
func TestRevokeReachesTheMachineWhileTheMailboxIsDown(t *testing.T) {
	f := newFleetWith(t, func(f *fleet) { f.copy = true })
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	keep(t, ctx, f.keeper())
	f.relay.mu.Lock()
	f.relay.down = true
	f.relay.mu.Unlock()
	cur, _ := f.m.Current()
	changed := f.m.Changed()
	if _, err := orgissuer.RevokeMachines(f.org.dir, []string{"m-web-1"}, f.clk.Now()); err != nil {
		t.Fatal(err)
	}
	f.untilRefused(t, cur, changed, hang, "the revoke did not reach the machine while the mailbox was down")
}
