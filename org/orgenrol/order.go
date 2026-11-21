// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"time"

	"github.com/nfltr/relay/org/orgpki"
)

// SendOrder posts the root's order (orgpki.RevokeOrder, signed on the
// root's machine: nfltr org approve) on orgID's enrol drop box and waits
// up to wait for the issuer's answer: the name it revoked, or
// ErrIssuerRefused with its reason (spec/orgmove/OrgDash.tla Apply).
func SendOrder(ctx context.Context, mb Mailbox, orgID string, o orgpki.SignedOrder, wait time.Duration) (string, error) {
	a, err := exchange(ctx, mb, orgID, orgpki.Request{ID: randomID(), Order: &o}, wait)
	return a.Revoked, err
}
