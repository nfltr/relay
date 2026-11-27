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

// Acts of an Order.
const (
	ActRevokeOrder = "revoke" // revoke Name at Serial
	// ActMoveOrder: move Name, at Serial, into Groups (nfltr
	// docs/decisions/one-group-2026-11-25.md; relay-server
	// spec/GroupMirror.tla Move; spec/proverif/orggroup.pv query 5,
	// BIND:group.movesig). The issuer applies it by re-certifying the name
	// with Groups and revoking every certificate of its enrolment so far.
	ActMoveOrder = "move"
)

// Order is what the root orders the issuer.
type Order struct {
	OrgID    string    `json:"org_id"`
	Act      string    `json:"act"`
	Name     string    `json:"name"`
	Serial   string    `json:"serial"` // a certificate of the name's current enrolment (since its last rebind), as StatusMember.Serial
	NotAfter time.Time `json:"not_after"`
	Groups   []string  `json:"groups,omitempty"` // a move's: the name's groups from now
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
	return signOrder(root, Order{OrgID: p.OrgID, Act: ActRevokeOrder, Name: name, Serial: serial, NotAfter: now.Add(OrderLife).UTC()})
}

// MoveOrder is the root's order to move name at serial into groups in the
// organisation p pins, void OrderLife after now. The caller has shown the
// owner what it signs (organisation, name, serial, groups: nfltr org
// approve).
func MoveOrder(p Pins, root crypto.Signer, name, serial string, groups []string, now time.Time) (SignedOrder, error) {
	if len(groups) == 0 {
		return SignedOrder{}, fmt.Errorf("%w: a move names the groups", ErrRefused)
	}
	return signOrder(root, Order{OrgID: p.OrgID, Act: ActMoveOrder, Name: name, Serial: serial, NotAfter: now.Add(OrderLife).UTC(), Groups: slices.Clone(groups)})
}

func signOrder(root crypto.Signer, o Order) (SignedOrder, error) {
	if o.Name == "" || o.Serial == "" {
		return SignedOrder{}, fmt.Errorf("%w: an order names a member and its serial", ErrRefused)
	}
	body, err := json.Marshal(o)
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
// current enrolment, not revoked yet; a move also a serial not moved already, into groups
// within the issuer's bound and not the name's own. It returns the order
// applied.
func (i *Issuer) ApplyOrder(s SignedOrder, now time.Time) (Order, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !verifyRootSig(i.root, append([]byte(orderPrefix), s.Body...), s.Sig) { // BIND:group.movesig, BIND:dash.ordersig
		return Order{}, fmt.Errorf("%w: the order is not the organisation root's signature", ErrRefused)
	}
	var o Order
	err := json.Unmarshal(s.Body, &o)
	n := i.names[o.Name]
	switch {
	case err != nil:
		err = fmt.Errorf("%w: the order: %v", ErrRefused, err)
	case o.OrgID != i.orgID:
		err = fmt.Errorf("%w: the order is of organisation %q, not %s", ErrRefused, o.OrgID, i.orgID)
	case o.Act != ActRevokeOrder && o.Act != ActMoveOrder:
		err = fmt.Errorf("%w: the order's act %q is not one this issuer applies", ErrRefused, o.Act)
	case !now.Before(o.NotAfter) || o.NotAfter.Sub(now) > OrderLife:
		err = fmt.Errorf("%w: the order is void (until %s)", ErrRefused, o.NotAfter.UTC().Format(time.RFC3339))
	case n == nil:
		err = fmt.Errorf("%w: %s is not enrolled", ErrRefused, o.Name)
	case !slices.Contains(n.serials[n.retired:], o.Serial):
		err = fmt.Errorf("%w: serial %s is not of %s's current enrolment", ErrRefused, o.Serial, o.Name)
	case n.revoked:
		err = fmt.Errorf("%w: %s is revoked already", ErrRefused, o.Name)
	case o.Act == ActMoveOrder:
		err = i.applyMove(o, n, now)
	default:
		err = i.revokeName(o.Name, now)
	}
	return o, err
}

// applyMove moves n, the name of move order o, into o's groups
// (GroupMirror.tla Move): one regrouped entry names the groups the name
// is certified with from now and revokes every certificate of it issued
// so far (they are in every CRL until they expire: mutant
// move-keeps-old-cert); the machine's renewal, which a revoked serial
// still may ask (the keeper asks at once: orgmachine RenewDue), brings
// the new groups. The CRL is due, so the next publish signs it and the
// status (its map moved, its CRL that one) together. An order of a serial
// moved already is refused (a replay moves nothing back). Callers hold mu.
func (i *Issuer) applyMove(o Order, n *nameRec, now time.Time) error {
	switch {
	case slices.Index(n.serials, o.Serial) < n.moved: // mutant move-replayed
		return fmt.Errorf("%w: serial %s of %s was moved already; move it again once the machine renewed into its new groups (nfltr org status)", ErrRefused, o.Serial, o.Name)
	case len(o.Groups) == 0 || !subset(o.Groups, i.cert.Subject.OrganizationalUnit): // mutant move-outside-bound
		return fmt.Errorf("%w: groups %v are outside the issuer's policy %v (nfltr org issuer renew --groups)", ErrRefused, o.Groups, i.cert.Subject.OrganizationalUnit)
	case sameGroups(o.Groups, n.groups):
		return fmt.Errorf("%w: %s is in groups %v already", ErrRefused, o.Name, n.groups)
	}
	if err := i.commit(Entry{Time: now, Act: ActRegrouped, Name: o.Name, Groups: slices.Clone(o.Groups), Serial: o.Serial}); err != nil {
		return err
	}
	groupLine(map[string]any{"ev": "move", "o": i.orgID, "n": o.Name, "s": o.Serial, "gs": o.Groups, "t": now.Unix()})
	return nil
}

// sameGroups: a and b hold the same groups (a certificate's OU is a set).
func sameGroups(a, b []string) bool { return subset(a, b) && subset(b, a) }
