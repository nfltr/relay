// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The root's access policy (nfltr docs/decisions/service-access-2026-11-25.md
// "2. Policy"; relay-server spec/GroupMirror.tla RuleAsk, RuleApply,
// RuleOnlyAsked; spec/proverif/svc_access.pv query 4): who may use which
// service and who approves access to it, signed by the root on the root's
// machine (nfltr access allow, one Touch ID) and carried by the relay to
// the issuer, which takes only the root's signature of its own
// organisation, newer than the one it holds, logs it and carries it in
// every signed status from then (the serving agents' rules: client/orgid
// Identity.TakeStatus). The relay can withhold or replay one; a replay
// changes nothing (Number), and it can forge none.

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// SignPolicy is the root's signature of p (its OrgID and Number set by
// the caller: the organisation p pins, one more than the issuer's). The
// caller has shown the owner what it signs.
func SignPolicy(root crypto.Signer, p orgid.Policy) (orgid.SignedPolicy, error) {
	if err := p.Valid(); err != nil {
		return orgid.SignedPolicy{}, err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return orgid.SignedPolicy{}, err
	}
	sig, err := crypto.SignMessage(root, rand.Reader, append([]byte(orgid.PolicyPrefix), body...), crypto.SHA256)
	if err != nil {
		return orgid.SignedPolicy{}, fmt.Errorf("root signature: %w", err)
	}
	return orgid.SignedPolicy{Body: body, Sig: sig}, nil
}

// TakePolicy takes the root's policy sp: signed by this organisation's
// root, of this organisation, valid, and numbered above the one held (a
// replay or an older one is refused: GroupMirror.tla mutant
// rule-without-root, the relay's own policy). It is logged, then carried
// in every SignedStatus. It returns the number held.
func (i *Issuer) TakePolicy(sp orgid.SignedPolicy, now time.Time) (int64, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	p, err := orgid.VerifyPolicy(sp, i.root, i.orgID)
	if err != nil {
		return i.policyNum, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	if p.Number <= i.policyNum {
		return i.policyNum, fmt.Errorf("%w: access policy %d is not newer than the one held (%d)", ErrRefused, p.Number, i.policyNum)
	}
	if err := i.commit(Entry{Time: now, Act: ActPolicy, Number: p.Number, Policy: sp.Body, RootSig: sp.Sig}); err != nil {
		return i.policyNum, err
	}
	return i.policyNum, nil
}

// Policy is the root's newest access policy the issuer holds (zero
// Number: none yet).
func (i *Issuer) Policy() (orgid.Policy, error) {
	i.mu.Lock()
	sp := i.policy
	i.mu.Unlock()
	if sp == nil {
		return orgid.Policy{OrgID: i.orgID}, nil
	}
	return orgid.VerifyPolicy(*sp, i.root, i.orgID)
}
