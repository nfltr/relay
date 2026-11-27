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
	People    []Person              `json:"people"`            // the roster (people.go), removed people included: the relay revokes their machines (relay-server spec/PersonEnrol.tla ApplyStatus)
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
	Person    string    `json:"person,omitempty"` // the name's person (PersonOf), "" for none
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

// ErrCRLDue: a move since the last CRL; the status is signed only after
// the CRL revoking the moved certificates (Issuer.CRL), so a status never
// shows a move whose old certificates its CRL does not list (relay-server
// spec/GroupMirror.tla Sign: the status and the CRL signed together;
// mutant status-before-crl).
var ErrCRLDue = errors.New("a move is not in a CRL yet: the status is signed after the CRL")

// SignedStatus is this issuer's status at now, signed with its key, with
// the CRL last signed (ErrCRLDue while a move waits for one).
func (i *Issuer) SignedStatus(now time.Time) (SignedStatus, error) {
	req, err := i.RenewalRequest(i.Groups())
	if err != nil {
		return SignedStatus{}, err
	}
	i.mu.Lock()
	if i.moveDue {
		i.mu.Unlock()
		return SignedStatus{}, ErrCRLDue
	}
	st := Status{OrgID: i.orgID, At: now.UTC(), Head: i.head, Issuer: i.cert.Raw, RootFP: orgid.Fingerprint(i.root),
		CRL: StatusCRL{Number: i.crlNumber, NextUpdate: i.crlNext}, Members: []StatusMember{}, Tokens: []StatusToken{}, Renewal: &req, Policy: i.policy}
	for name, n := range i.names {
		if len(st.Members) == MaxStatusMembers {
			st.Truncated = true
			break
		}
		m := StatusMember{Name: name, Groups: slices.Clone(n.groups), MachineID: n.machineID, Person: n.dev.Person, Revoked: n.revoked}
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
	st.People = []Person{}
	for email, p := range i.roster.people {
		if len(st.People) == MaxStatusMembers {
			st.Truncated = true
			break
		}
		st.People = append(st.People, Person{Email: email, Role: p.role, Removed: p.removed})
	}
	for k := range i.denied { // a removed person an owner's code enrolled: not in the roster
		if email, ok := strings.CutPrefix(k, "person:"); ok && i.roster.people[email] == nil && len(st.People) < MaxStatusMembers {
			st.People = append(st.People, Person{Email: email, Removed: true})
		}
	}
	key := i.key
	groupStatusLine(st)
	i.mu.Unlock()
	slices.SortFunc(st.People, func(a, b Person) int { return strings.Compare(a.Email, b.Email) })
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

// ErrTruncated: the log lacks the head of a status this issuer published,
// so lines at its tail are lost (a disk or a copy rolled back); acts they
// held (revocations, CRL Numbers) would be undone. A copy of a lost issuer
// comes back with nfltr org move send --restored (Restore), never by
// serving the shorter log.
var ErrTruncated = errors.New("the issuer's log ends before the head it published: lines at its tail are lost")

// CheckPublishedHead holds the log to msg, the relay's copy of the
// organisation's signed status (orgid.StatusCopy): when it is this
// organisation's, signed under its root, and names a head this log does
// not hold, the log lost lines at its tail (ErrTruncated; lane SECFIX2,
// review S19, mutant truncation-unseen). A status from before a restore
// (the lost issuer's) is not held against the restored log, nor one that
// does not verify (the relay's word is no evidence).
func (i *Issuer) CheckPublishedHead(msg []byte) error {
	var s SignedStatus
	if json.Unmarshal(msg, &s) != nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	st, _, err := VerifyStatus(s, i.root)
	if err != nil || st.OrgID != i.orgID {
		return nil
	}
	if _, ok := i.heads[st.Head]; ok || (!i.restoredAt.IsZero() && st.At.Before(i.restoredAt)) {
		return nil
	}
	return fmt.Errorf("%w: the relay holds this issuer's status of %s at head %s, not in this log of %d lines (restore it with nfltr org move send --restored)", ErrTruncated, st.At.UTC().Format(time.RFC3339), st.Head, len(i.heads))
}
