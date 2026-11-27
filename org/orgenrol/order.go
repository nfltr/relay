// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/nfltr/relay/client/orgid"
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

// SendPolicy posts the root's access policy (orgpki.SignPolicy, signed on
// the root's machine: nfltr access allow) on orgID's enrol drop box and
// waits up to wait for the issuer's answer: the number of the policy it
// holds, or ErrIssuerRefused with its reason (an older or replayed one).
func SendPolicy(ctx context.Context, mb Mailbox, orgID string, p orgid.SignedPolicy, wait time.Duration) (int64, error) {
	a, err := exchange(ctx, mb, orgID, orgpki.Request{ID: randomID(), Policy: &p}, wait)
	return a.Policy, err
}

// SendRenewal posts the root's renewal answer (orgpki.SignIssuerRenewal,
// signed on the root's machine: nfltr org approve of a renew wish) on
// orgID's enrol drop box and waits up to wait for the issuer to install
// it: the NotAfter of the issuer certificate it now holds, or
// ErrIssuerRefused with its reason (spec/orgmove/OrgDash.tla Apply).
func SendRenewal(ctx context.Context, mb Mailbox, orgID string, r orgpki.IssuerRenewal, wait time.Duration) (time.Time, error) {
	a, err := exchange(ctx, mb, orgID, orgpki.Request{ID: randomID(), IssuerRenewal: &r}, wait)
	if err != nil {
		return time.Time{}, err
	}
	c, err := x509.ParseCertificate(a.Issuer)
	if err != nil {
		return time.Time{}, fmt.Errorf("the issuer's answer names no certificate: %w", err)
	}
	return c.NotAfter, nil
}

// SendGrant posts a grant act (orgpki.SignGrant: a member machine's
// request, an approver's answer, a revoke; nfltr access request|approve|
// deny|revoke) on orgID's enrol drop box and waits up to wait for the
// issuer's answer: what it did, or ErrIssuerRefused with its reason. A
// grant rides the issuer's next status (its holder's agent presents it).
func SendGrant(ctx context.Context, mb Mailbox, orgID string, g orgpki.GrantRequest, wait time.Duration) (orgpki.GrantAnswer, error) {
	a, err := exchange(ctx, mb, orgID, orgpki.Request{ID: randomID(), Grant: &g}, wait)
	if err != nil {
		return orgpki.GrantAnswer{}, err
	}
	if a.Grant == nil {
		return orgpki.GrantAnswer{}, fmt.Errorf("the issuer's answer names no grant act")
	}
	return *a.Grant, nil
}
