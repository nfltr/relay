// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The root's order to the issuer (nfltr docs/decisions/org-dashboard-2026-11-21.md
// "Revoke"; spec/orgmove/OrgDash.tla Approve, Apply; spec/proverif/orgdash.pv
// queries 3-4): a revoke the owner asked for in the dashboard, signed by
// the root on the root's machine after the owner's approval (one Touch ID
// on a prompt naming organisation, name and serial), carried by the relay
// to the issuer, which applies only an order the root signed
// (BIND:dash.ordersig), of its own organisation (BIND:dash.org), to the
// enrolment it names (BIND:dash.serial). The relay can withhold or replay
// one; a replay revokes nothing new.

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// orderPrefix is what an order's root signature covers before the body.
// It is not DER (an x509 TBS starts with 0x30) and not a checkpoint.
const orderPrefix = "nfltr-org-order-v1\x00"

// OrderLife bounds an order's NotAfter from its signing: a withheld order
// is void after it.
const OrderLife = 24 * time.Hour

// ActRevokeOrder is an Order's Act: revoke Name at Serial.
const ActRevokeOrder = "revoke"

// Order is what the root orders the issuer.
type Order struct {
	OrgID    string    `json:"org_id"`
	Act      string    `json:"act"`
	Name     string    `json:"name"`
	Serial   string    `json:"serial"` // a certificate of the name's current enrolment (since its last rebind)
	NotAfter time.Time `json:"not_after"`
}

// SignedOrder is an Order's JSON bytes and the root's signature over the
// order prefix ("nfltr-org-order-v1" NUL) and them.
type SignedOrder struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
}

// RevokeOrder is the root's order to revoke name at serial in the
// organisation p pins, void OrderLife after now. The caller has shown the
// owner what it signs (nfltr org approve).
func RevokeOrder(p Pins, root crypto.Signer, name, serial string, now time.Time) (SignedOrder, error) {
	if name == "" || serial == "" {
		return SignedOrder{}, fmt.Errorf("%w: an order names a member and its serial", ErrRefused)
	}
	body, err := json.Marshal(Order{OrgID: p.OrgID, Act: ActRevokeOrder, Name: name, Serial: serial, NotAfter: now.Add(OrderLife).UTC()})
	if err != nil {
		return SignedOrder{}, err
	}
	sig, err := crypto.SignMessage(root, rand.Reader, append([]byte(orderPrefix), body...), crypto.SHA256)
	if err != nil {
		return SignedOrder{}, fmt.Errorf("root signature: %w", err)
	}
	return SignedOrder{Body: body, Sig: sig}, nil
}

// ApplyOrder applies the root's order: signed by this organisation's root,
// of this organisation, unexpired, and naming a serial of the name's
// current enrolment, not revoked yet. It returns the name revoked.
func (i *Issuer) ApplyOrder(s SignedOrder, now time.Time) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !verifyRootSig(i.root, append([]byte(orderPrefix), s.Body...), s.Sig) {
		return "", fmt.Errorf("%w: the order is not the organisation root's signature", ErrRefused)
	}
	var o Order
	err := json.Unmarshal(s.Body, &o)
	n := i.names[o.Name]
	switch {
	case err != nil:
		err = fmt.Errorf("%w: the order: %v", ErrRefused, err)
	case o.OrgID != i.orgID:
		err = fmt.Errorf("%w: the order is of organisation %q, not %s", ErrRefused, o.OrgID, i.orgID)
	case o.Act != ActRevokeOrder:
		err = fmt.Errorf("%w: the order's act %q is not one this issuer applies", ErrRefused, o.Act)
	case !now.Before(o.NotAfter) || o.NotAfter.Sub(now) > OrderLife:
		err = fmt.Errorf("%w: the order is void (until %s)", ErrRefused, o.NotAfter.UTC().Format(time.RFC3339))
	case n == nil:
		err = fmt.Errorf("%w: %s is not enrolled", ErrRefused, o.Name)
	case !slices.Contains(n.serials[n.retired:], o.Serial):
		err = fmt.Errorf("%w: serial %s is not of %s's current enrolment", ErrRefused, o.Serial, o.Name)
	case n.revoked:
		err = fmt.Errorf("%w: %s is revoked already", ErrRefused, o.Name)
	}
	if err != nil {
		return "", err
	}
	return o.Name, i.revokeName(o.Name, now)
}
