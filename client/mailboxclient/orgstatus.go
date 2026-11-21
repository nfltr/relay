// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package mailboxclient

import (
	"context"
	"net/url"
)

// The relay's copy of an organisation's signed status (relay-server
// /api/v1/org-status/<org id>, nfltr docs/decisions/org-dashboard-2026-11-21.md):
// what the issuer signed of its members, tokens and certificate, for the
// dashboard and `nfltr org status --relay`. Untrusted like the CRL copy: a
// reader takes it by its signature under the root it pins
// (orgpki.VerifyStatus). A relay holds one organisation per account and
// refuses another's put (409).

// OrgStatusPath is the copy's route for orgID.
func OrgStatusPath(orgID string) string { return "/api/v1/org-status/" + url.PathEscape(orgID) }

// maxOrgStatus bounds a status read (the relay refuses a larger put).
const maxOrgStatus = 1 << 20

// OrgStatus is the relay's copy for orgID (an orgpki.SignedStatus, JSON);
// nil when the relay holds none.
func (c Client) OrgStatus(ctx context.Context, orgID string) ([]byte, error) {
	return c.orgCopy(ctx, OrgStatusPath(orgID), maxOrgStatus)
}

// PutOrgStatus keeps msg (an orgpki.SignedStatus, JSON) as the relay's
// copy for orgID.
func (c Client) PutOrgStatus(ctx context.Context, orgID string, msg []byte) error {
	return c.putOrgCopy(ctx, OrgStatusPath(orgID), msg)
}
