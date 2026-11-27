// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package mailboxclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

// The owner's wishes from the dashboard (relay-server /api/v1/org-wishes/<org id>,
// nfltr docs/decisions/org-dashboard-2026-11-21.md "Revoke", "Renew"): a
// revoke or a renewal the owner pressed, waiting for the root's machine
// (nfltr org approve), which shows each and signs only what the owner
// approves there. The relay can make any wish: a wish commits nothing.

// OrgWish is one pending wish.
type OrgWish struct {
	ID     string    `json:"id"`
	Act    string    `json:"act"` // "revoke" or "renew"
	Name   string    `json:"name,omitempty"`
	Serial string    `json:"serial,omitempty"`
	Groups []string  `json:"groups,omitempty"` // a renewal's groups (widen), none: the issuer's
	At     time.Time `json:"at"`
}

// OrgWishesPath is the wishes' route for orgID.
func OrgWishesPath(orgID string) string { return "/api/v1/org-wishes/" + url.PathEscape(orgID) }

// OrgWishes is the relay's pending wishes for orgID.
func (c Client) OrgWishes(ctx context.Context, orgID string) ([]OrgWish, error) {
	data, err := c.orgCopy(ctx, OrgWishesPath(orgID), maxOrgCRL)
	if err != nil || data == nil {
		return nil, err
	}
	var out struct {
		Wishes []OrgWish `json:"wishes"`
	}
	return out.Wishes, json.Unmarshal(data, &out)
}

// DropOrgWish removes wish id of orgID (approved or declined).
func (c Client) DropOrgWish(ctx context.Context, orgID, id string) error {
	code, data, err := c.raw(ctx, http.MethodDelete, OrgWishesPath(orgID)+"/"+url.PathEscape(id), nil, maxOrgCRL)
	if err == nil && code/100 != 2 && code != http.StatusNotFound {
		err = decodeError(code, data)
	}
	return err
}
