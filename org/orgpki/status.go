// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The issuer's signed status (nfltr docs/decisions/org-dashboard-2026-11-21.md
// "Status"; spec/orgmove/OrgDash.tla ShownSigned, ShownNotAfterTrue;
// spec/proverif/orgdash.pv queries 1-2, BIND:dash.statussig,
// BIND:dash.notafter): what the dashboard and `nfltr org status --relay`
// show of the organisation (the issuer certificate, its members, its unused
// tokens, the CRL) as the issuer signed it. The relay holds and serves it
// and can withhold or replay one; it cannot make one. The signature is over
// the body's exact bytes, so a browser checks it without re-encoding JSON.

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// statusPrefix is what the status signature covers before the body.
const statusPrefix = "nfltr-org-status-v1\x00"

// MaxStatusMembers bounds the members and tokens a status lists (the rest:
// Truncated), so a status stays within the relay's put bound.
const MaxStatusMembers = 2000

// Status is the issuer's state for its readers.
type Status struct {
	OrgID     string                `json:"org_id"`
	At        time.Time             `json:"at"`
	Head      string                `json:"head"`
	Issuer    []byte                `json:"issuer"` // DER: days left are its NotAfter's, no other field's
	RootFP    string                `json:"root_fp"`
	CRL       StatusCRL             `json:"crl"`
	Members   []StatusMember        `json:"members"`
	Tokens    []StatusToken         `json:"tokens"`
	Renewal   *IssuerRenewalRequest `json:"renewal,omitempty"` // the issuer's request at Head, for the root's machine
	Policy    *orgid.SignedPolicy   `json:"policy,omitempty"`  // the root's access policy (policy.go): the serving agents' rules
	Requests  []StatusGrantRequest  `json:"requests"`          // open grant requests (grant.go)
	Grants    []StatusGrant         `json:"grants"`            // grants in force: their holders present them
	Truncated bool                  `json:"truncated,omitempty"`
}

// StatusCRL is the issuer's last CRL.
type StatusCRL struct {
	Number     int64     `json:"number"`
	NextUpdate time.Time `json:"next_update"`
}

// StatusMember is an enrolled name: Serial its newest certificate's.
type StatusMember struct {
	Name      string    `json:"name"`
	Serial    string    `json:"serial"`
	Groups    []string  `json:"groups"`
	MachineID string    `json:"machine_id,omitempty"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   bool      `json:"revoked,omitempty"`
}

// StatusToken is an unused, unexpired token; never its secret.
type StatusToken struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Groups  []string  `json:"groups"`
	Expires time.Time `json:"expires"`
}

// SignedStatus is a Status's JSON bytes and the issuer key's signature over
// "nfltr-org-status-v1" NUL and them.
type SignedStatus struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
}

// SignedStatus is this issuer's status at now, signed with its key.
func (i *Issuer) SignedStatus(now time.Time) (SignedStatus, error) {
	req, err := i.RenewalRequest(i.Groups())
	if err != nil {
		return SignedStatus{}, err
	}
	i.mu.Lock()
	st := Status{OrgID: i.orgID, At: now.UTC(), Head: i.head, Issuer: i.cert.Raw, RootFP: orgid.Fingerprint(i.root),
		CRL: StatusCRL{Number: i.crlNumber, NextUpdate: i.crlNext}, Members: []StatusMember{}, Tokens: []StatusToken{}, Renewal: &req, Policy: i.policy}
	for name, n := range i.names {
		if len(st.Members) == MaxStatusMembers {
			st.Truncated = true
			break
		}
		m := StatusMember{Name: name, Groups: slices.Clone(n.groups), MachineID: n.machineID, Revoked: n.revoked}
		if len(n.serials) > 0 {
			m.Serial = n.serials[len(n.serials)-1]
			if c := i.certs[m.Serial]; c != nil {
				m.NotAfter = c.notAfter
			}
		}
		st.Members = append(st.Members, m)
	}
	for id, t := range i.tokens {
		if len(st.Tokens) == MaxStatusMembers {
			st.Truncated = true
			break
		}
		if !t.void && now.Before(t.expires) && !i.tokenUsed(id, t) {
			st.Tokens = append(st.Tokens, StatusToken{ID: id, Name: t.name, Groups: slices.Clone(t.groups), Expires: t.expires})
		}
	}
	var gt bool
	st.Requests, st.Grants, gt = i.statusGrants(now)
	st.Truncated = st.Truncated || gt
	key := i.key
	i.mu.Unlock()
	slices.SortFunc(st.Members, func(a, b StatusMember) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(st.Tokens, func(a, b StatusToken) int { return strings.Compare(a.ID, b.ID) })
	body, err := json.Marshal(st)
	if err != nil {
		return SignedStatus{}, err
	}
	return SignedStatus{Body: body, Sig: ed25519.Sign(key, append([]byte(statusPrefix), body...))}, nil
}

// tokenUsed reports whether token id can no longer enrol (i.mu held): a
// token is for a name not enrolled (Enrol), a rebind token until one of
// the name's certificates redeemed it.
func (i *Issuer) tokenUsed(id string, t *tokenRec) bool {
	n := i.names[t.name]
	return n != nil && (!t.rebind || slices.ContainsFunc(n.serials, func(sn string) bool { return i.certs[sn].token == id }))
}

// ErrStatus is a status a reader refuses.
var ErrStatus = errors.New("organisation status refused")

// VerifyStatus is a pinned reader's check (BIND:dash.statussig): s's body
// signed by the key of the issuer certificate it carries, that certificate
// signed by root (the organisation's, the reader's pin). It returns the
// status and that certificate, whose NotAfter is the days left a reader
// shows (BIND:dash.notafter).
func VerifyStatus(s SignedStatus, root *x509.Certificate) (Status, *x509.Certificate, error) {
	st, iss, err := CheckStatusSignature(s)
	if err != nil {
		return Status{}, nil, err
	}
	if err := iss.CheckSignatureFrom(root); err != nil {
		return Status{}, nil, fmt.Errorf("%w: its issuer certificate is not the organisation root's: %v", ErrStatus, err)
	}
	return st, iss, nil
}

// CheckStatusSignature checks only that s's body is signed by the issuer
// certificate inside it (a relay's sanity check, as for the CRL copy): it
// proves nothing about the organisation without VerifyStatus's root.
func CheckStatusSignature(s SignedStatus) (Status, *x509.Certificate, error) {
	var st Status
	if err := json.Unmarshal(s.Body, &st); err != nil {
		return Status{}, nil, fmt.Errorf("%w: %v", ErrStatus, err)
	}
	iss, err := orgid.StatusIssuer(s.Body, s.Sig)
	if err != nil {
		return Status{}, nil, fmt.Errorf("%w: %v", ErrStatus, err)
	}
	return st, iss, nil
}
