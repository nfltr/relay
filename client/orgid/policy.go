// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

// The organisation's access rules (nfltr docs/decisions/service-access-2026-11-25.md
// "2. Policy"; relay-server spec/GroupMirror.tla PeerRuleAdmits,
// PeerRuleStaleBound; spec/proverif/svc_access.pv query 4,
// BIND:svc.rulesig, BIND:svc.apprpol): who may use which service, and who
// approves access to it, as the root signed them (`nfltr access allow` on
// the root's machine). The issuer carries the root's newest policy in its
// signed status, so the relay can withhold or replay one only within the
// status's life (TakeStatus): it can forge none. The serving agent's check
// is an exact match of the client's certified principal against the
// rules: no expression language.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// PolicyPrefix is what the root's policy signature covers before the
// body. It is not DER (an x509 TBS starts with 0x30) and no other signed
// message's prefix.
const PolicyPrefix = "nfltr-org-policy-v1\x00"

// statusPrefix is what the issuer's status signature covers before the
// body (relay org orgpki.SignedStatus).
const statusPrefix = "nfltr-org-status-v1\x00"

// MaxPolicyRules bounds a policy's rules and approver entries each.
const MaxPolicyRules = 1000

// The kinds of a principal or a place, as "<kind>:<name>".
const (
	KindGroup   = "group"
	KindMachine = "machine"
	KindPerson  = "person"
)

// AnyService is a rule's Service for every service of its place.
const AnyService = "*"

// Policy is the root's access policy for the organisation, every rule and
// approver entry at once (Number: the root's count, higher wins).
type Policy struct {
	OrgID     string     `json:"org_id"`
	Number    int64      `json:"number"`
	Rules     []Rule     `json:"rules"`
	Approvers []Approver `json:"approvers,omitempty"`
}

// Rule lets Who use Service at Where: Who a "group:", "machine:" or
// "person:" principal, Where a "group:" or "machine:" place (the serving
// machine, or every machine of a group), Service a service name or
// AnyService.
type Rule struct {
	Who     string `json:"who"`
	Where   string `json:"where"`
	Service string `json:"service"`
}

// Approver names the persons who approve a grant of Service at Where
// (nfltr access request; SA4's issuer checks an approval against it).
type Approver struct {
	Where   string   `json:"where"`
	Service string   `json:"service"`
	People  []string `json:"people"`
}

// SignedPolicy is a Policy's JSON bytes and the root's signature over
// PolicyPrefix and them.
type SignedPolicy struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
}

// ErrPolicy is a policy a reader refuses.
var ErrPolicy = errors.New("organisation access policy refused")

// Valid reports why p is not a policy a root may sign, nil when it is.
func (p Policy) Valid() error {
	if p.OrgID == "" || p.Number < 1 {
		return fmt.Errorf("%w: it names no organisation or number", ErrPolicy)
	}
	if len(p.Rules) > MaxPolicyRules || len(p.Approvers) > MaxPolicyRules {
		return fmt.Errorf("%w: more than %d rules or approver entries", ErrPolicy, MaxPolicyRules)
	}
	for _, r := range p.Rules {
		if !principal(r.Who, KindGroup, KindMachine, KindPerson) || !principal(r.Where, KindGroup, KindMachine) || !serviceName(r.Service) {
			return fmt.Errorf("%w: rule %s %s/%s", ErrPolicy, r.Who, r.Where, r.Service)
		}
	}
	for _, a := range p.Approvers {
		if !principal(a.Where, KindGroup, KindMachine) || !serviceName(a.Service) || a.Service == AnyService || len(a.People) == 0 ||
			slices.ContainsFunc(a.People, func(n string) bool { return !principal(KindPerson+":"+n, KindPerson) }) {
			return fmt.Errorf("%w: approvers of %s/%s", ErrPolicy, a.Where, a.Service)
		}
	}
	return nil
}

func principal(s string, kinds ...string) bool {
	k, n, ok := strings.Cut(s, ":")
	return ok && n != "" && slices.Contains(kinds, k) && !strings.ContainsAny(n, " /:\x00")
}

func serviceName(s string) bool { return s != "" && !strings.ContainsAny(s, " /:\x00") }

// RootSigned reports whether sig is root's key's signature of msg (an
// ECDSA root signs its SHA-256, an Ed25519 root the message).
func RootSigned(root *x509.Certificate, msg, sig []byte) bool {
	switch pub := root.PublicKey.(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pub, sum[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, msg, sig)
	}
	return false
}

// VerifyPolicy is the policy sp carries when root signed it, of the
// organisation orgID, and valid (BIND:svc.rulesig: a rule only under the
// root's key, svc_access.pv mutant rule-unsigned).
func VerifyPolicy(sp SignedPolicy, root *x509.Certificate, orgID string) (Policy, error) {
	if !RootSigned(root, append([]byte(PolicyPrefix), sp.Body...), sp.Sig) {
		return Policy{}, fmt.Errorf("%w: not the organisation root's signature", ErrPolicy)
	}
	var p Policy
	if err := json.Unmarshal(sp.Body, &p); err != nil {
		return Policy{}, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	if p.OrgID != orgID {
		return Policy{}, fmt.Errorf("%w: it is organisation %q's, not %q's", ErrPolicy, p.OrgID, orgID)
	}
	return p, p.Valid()
}

// Admits reports whether a rule lets client (a checked certificate: its
// name, groups and person) use service on the serving machine self (its
// own name and groups).
func (p Policy) Admits(client, self Checked, service string) bool {
	_, ok := p.admitting(client, self, service)
	return ok
}

// admitting is the first rule of p that admits client to service on self.
func (p Policy) admitting(client, self Checked, service string) (Rule, bool) {
	i := slices.IndexFunc(p.Rules, func(r Rule) bool {
		return (r.Service == service || r.Service == AnyService) && matches(r.Who, client) && matches(r.Where, self)
	})
	if i < 0 {
		return Rule{}, false
	}
	return p.Rules[i], true
}

// matches reports whether a "<kind>:<name>" principal names c: one of its
// groups, its machine name, or its person.
func matches(who string, c Checked) bool {
	k, n, _ := strings.Cut(who, ":")
	switch k {
	case KindGroup:
		return slices.Contains(c.Groups, n)
	case KindMachine:
		return c.Name == n
	case KindPerson:
		return c.Person != "" && c.Person == n
	}
	return false
}

// Approves reports whether the policy names person an approver of service
// at where (a "group:" or "machine:" place; BIND:svc.apprpol: an approval
// counts only by an approver the root's policy names for that service,
// svc_access.pv mutant policy-unsigned).
func (p Policy) Approves(person, where, service string) bool {
	return person != "" && slices.ContainsFunc(p.Approvers, func(a Approver) bool {
		return a.Where == where && a.Service == service && slices.Contains(a.People, person)
	})
}

// StatusIssuer is the issuer certificate a signed status carries, when
// sig is that certificate's key's signature of body (relay org
// orgpki.CheckStatusSignature): nothing about the organisation without a
// check of that certificate to the root.
func StatusIssuer(body, sig []byte) (*x509.Certificate, error) {
	var st struct {
		Issuer []byte `json:"issuer"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, err
	}
	iss, err := x509.ParseCertificate(st.Issuer)
	if err != nil {
		return nil, fmt.Errorf("its issuer certificate: %w", err)
	}
	pub, ok := iss.PublicKey.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pub, append([]byte(statusPrefix), body...), sig) {
		return nil, errors.New("not signed by its issuer certificate's key")
	}
	return iss, nil
}

// heldPolicy is the policy of the newest status an Identity took: the
// status's signing time and its life (its CRL's NextUpdate, capped by its
// issuer's NotAfter).
type heldPolicy struct {
	at, until time.Time
	policy    Policy
	root      *x509.Certificate // the root it was taken under: its rules end with it
}

// statusPolicy is the policy of a relay org orgpki.SignedStatus (JSON)
// when the status is the organisation's: signed by an issuer certificate
// v would admit (under its root, unexpired at now, not on the root's CRL
// of issuers: review S5), of v's organisation, unexpired at now, carrying
// a policy the root signed (none: no rules). Freshness is the caller's
// (newer At only).
func statusPolicy(msg []byte, v *Verifier, now time.Time) (heldPolicy, error) {
	var sm struct {
		Body []byte `json:"body"`
		Sig  []byte `json:"sig"`
	}
	if err := json.Unmarshal(msg, &sm); err != nil {
		return heldPolicy{}, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	iss, err := StatusIssuer(sm.Body, sm.Sig)
	if err != nil {
		return heldPolicy{}, fmt.Errorf("%w: the status: %v", ErrPolicy, err)
	}
	v.mu.Lock()
	root, orgID := v.root, v.orgID
	_, err = v.verify(iss, nil, "", now)
	v.mu.Unlock()
	if err != nil {
		return heldPolicy{}, fmt.Errorf("%w: the status's issuer certificate is not one of the organisation root's in force: %v", ErrPolicy, err)
	}
	var st struct {
		OrgID string    `json:"org_id"`
		At    time.Time `json:"at"`
		CRL   struct {
			NextUpdate time.Time `json:"next_update"`
		} `json:"crl"`
		Policy *SignedPolicy `json:"policy"`
	}
	if err := json.Unmarshal(sm.Body, &st); err != nil {
		return heldPolicy{}, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	if st.OrgID != orgID {
		return heldPolicy{}, fmt.Errorf("%w: the status is organisation %q's, not %q's", ErrPolicy, st.OrgID, orgID)
	}
	until := st.CRL.NextUpdate
	if iss.NotAfter.Before(until) {
		until = iss.NotAfter
	}
	if !now.Before(until) {
		return heldPolicy{}, fmt.Errorf("%w: the status of %s lapsed at %s", ErrPolicy, st.At.Format(time.RFC3339), until.Format(time.RFC3339))
	}
	h := heldPolicy{at: st.At, until: until, root: root}
	if st.Policy != nil {
		if h.policy, err = VerifyPolicy(*st.Policy, root, orgID); err != nil {
			return heldPolicy{}, err
		}
	}
	return h, nil
}

// Rules are the access rules of the newest organisation status a serving
// machine took (Take), for its check of a client (Admit); the zero value
// holds none, and admits nobody. Identity and relay org orgmachine.Machine
// each hold one.
type Rules struct {
	mu   sync.Mutex
	held *heldPolicy
	// The newest rules number and status time this machine took under the
	// root of fingerprint floorRoot (MarksFile): a status below them is
	// refused after a restart too.
	floorRoot string
	floorNum  int64
	floorAt   time.Time
}

// Take takes the organisation's signed status msg (relay org
// orgpki.SignedStatus, JSON; the relay's copy) for its access rules: one
// an issuer of v's root signed, of v's organisation, unexpired, newer
// than the one held under that root (GroupMirror.tla PeerTake: mutants
// peer-rule-unsigned, peer-rule-older): higher rules, or the same under a
// later status. Rules held under a rotated-out root are replaced whatever
// their number (RulesFollowRotation). took: it is newer, the caller's
// sessions are to be checked again.
func (r *Rules) Take(msg []byte, v *Verifier, now time.Time) (took bool, err error) {
	h, err := statusPolicy(msg, v, now)
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.floorRoot == Fingerprint(h.root) && (h.policy.Number < r.floorNum || h.at.Before(r.floorAt)) {
		return false, fmt.Errorf("the status (rules %d, of %s) is older than the newest this machine took (rules %d, of %s): a replay", h.policy.Number, h.at.UTC().Format(time.RFC3339), r.floorNum, r.floorAt.UTC().Format(time.RFC3339))
	}
	// Newer: higher rules (the issuer numbers them up only), or the same
	// rules under a later status (a later life). A status the relay
	// replays is not newer.
	if old := r.held; old != nil && old.root.Equal(h.root) && (h.policy.Number < old.policy.Number || h.policy.Number == old.policy.Number && !h.at.After(old.at)) {
		return false, nil
	}
	r.held = &h
	return true, nil
}

// admit admits client (a checked certificate) to one of services on self
// (the serving machine's name and groups) by a rule (GroupMirror.tla
// PeerRuleAdmits) taken under root, the one the verifier pins now: fail
// closed with no rules, lapsed ones or a rotated-out root's
// (RulesFollowRotation). until is the earlier of the client certificate's
// and the rules' ends; rule is the one that admitted.
func (r *Rules) admit(client, self Checked, services []string, root *x509.Certificate, now time.Time) (until time.Time, rule Rule, err error) {
	r.mu.Lock()
	pol := r.held
	r.mu.Unlock()
	switch {
	case pol == nil || !pol.root.Equal(root):
		return time.Time{}, Rule{}, errors.New("no access rules from the organisation's status yet: fail closed (the agent reads it from the relay)")
	case !now.Before(pol.until):
		return time.Time{}, Rule{}, fmt.Errorf("the organisation's access rules lapsed at %s (status of %s): fail closed until the issuer is heard from", pol.until.Format(time.RFC3339), pol.at.Format(time.RFC3339))
	}
	for _, s := range services {
		if rule, ok := pol.policy.admitting(client, self, s); ok {
			if client.Until.Before(pol.until) {
				return client.Until, rule, nil
			}
			return pol.until, rule, nil
		}
	}
	return time.Time{}, Rule{}, fmt.Errorf("no access rule lets %s use %s/%s (nfltr access allow on the root's machine)", client.Name, self.Name, strings.Join(services, ","))
}
