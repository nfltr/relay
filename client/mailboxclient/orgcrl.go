// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package mailboxclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// The relay's own copy of an organisation's newest CRL message (relay-server
// /api/v1/org-crl/<org id>, nfltr docs/decisions/crl-off-mailbox-2026-11-20.md):
// a carrier of the CRL apart from the mailbox service, kept in the relay's
// process for the caller's account. Like the mailbox it is untrusted: a
// member takes what it reads by the CRL's signature (orgid TakeCRL), never
// by where it came from (spec/enrol/CrlCarriers.tla).

// OrgCRLPath is the copy's route for orgID.
func OrgCRLPath(orgID string) string { return "/api/v1/org-crl/" + url.PathEscape(orgID) }

// maxOrgCRL bounds a copy read (the relay refuses a larger put).
const maxOrgCRL = 64 << 10

// OrgCRL is the relay's copy for orgID (an orgid.CRLMessage, JSON); nil
// when the relay holds none.
func (c Client) OrgCRL(ctx context.Context, orgID string) ([]byte, error) {
	return c.orgCopy(ctx, OrgCRLPath(orgID), maxOrgCRL)
}

// PutOrgCRL keeps msg (an orgid.CRLMessage, JSON) as the relay's copy for
// orgID.
func (c Client) PutOrgCRL(ctx context.Context, orgID string, msg []byte) error {
	return c.putOrgCopy(ctx, OrgCRLPath(orgID), msg)
}

// orgCopy reads a copy route (nil: none held), at most limit bytes.
func (c Client) orgCopy(ctx context.Context, path string, limit int64) ([]byte, error) {
	code, data, err := c.raw(ctx, http.MethodGet, path, nil, limit)
	switch {
	case err != nil:
		return nil, err
	case code == http.StatusNotFound:
		return nil, nil
	case code/100 != 2:
		return nil, decodeError(code, data)
	}
	return data, nil
}

func (c Client) putOrgCopy(ctx context.Context, path string, msg []byte) error {
	code, data, err := c.raw(ctx, http.MethodPut, path, msg, maxOrgCRL)
	if err == nil && code/100 != 2 {
		err = decodeError(code, data)
	}
	return err
}

func (c Client) raw(ctx context.Context, method, path string, body []byte, limit int64) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.ProxyURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	client := c.HTTP
	if client == nil {
		client = relayHTTP()
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	return resp.StatusCode, data, err
}
