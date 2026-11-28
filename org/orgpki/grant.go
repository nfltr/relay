// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// Grants at the issuer (nfltr docs/decisions/service-access-2026-11-25.md
// "Grants"; spec/grant/Grant.tla Request, Sign, Deny, Revoke, Publish;
// spec/proverif/svc_access.pv query 2, BIND:svc.apprall, BIND:svc.apprpol):
// a member machine asks for one service for a duration (nfltr access
// request), an approver the root's policy names for that service approves
// or denies it with their machine's key (nfltr access approve|deny), and
// the issuer signs a grant certificate (client/orgid grant.go) for the
// requester's key once per request, the approval over the whole request,
// never the requester's own. A deny is the request's final answer. A
// revoke (an approver of the service, the owner, a removal of the
// grant's person or machine) lists the grant's serial on every CRL until
// the grant ends. The relay carries every act and can withhold or replay
// one; a replay changes nothing (the request id is answered once) and it
// can forge none.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// The acts of a GrantAct.
const (
	GrantAsk     = "request"
	GrantApprove = "approve"
	GrantDeny    = "deny"
	GrantRevoke  = "revoke"
)

// MaxGrantFor bounds a request's duration: a grant is elevated access for
// a task, not a standing rule (nfltr access allow is that).
const MaxGrantFor = 7 * 24 * time.Hour

// GrantAct is an act on a grant: a request (ID a new random id, Where,
// Service, For, Reason), an approval or a denial of request ID (Digest:
// the SHA-256 of the request's signed body, so the act covers the whole
// request, BIND:svc.apprall), or a revoke of grant ID (its serial, hex).
type GrantAct struct {
	OrgID    string    `json:"org_id"`
	Act      string    `json:"act"`
	ID       string    `json:"id"`
	Where    string    `json:"where,omitempty"`
	Service  string    `json:"service,omitempty"`
	ForS     int64     `json:"for_s,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Digest   string    `json:"digest,omitempty"`
	NotAfter time.Time `json:"not_after"`
}

// GrantRequest is a GrantAct's JSON bytes signed over the prefix
// "nfltr-org-grant-v1" NUL and them: by the key of Cert, a member
// machine's certificate (the requester's, an approver's), or by the root
// (no Cert: the owner's revoke or deny).
type GrantRequest struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
	Cert []byte `json:"cert,omitempty"`
}

const grantPrefix = "nfltr-org-grant-v1\x00"

// SignGrant signs a, void OrderLife after now: with key, the machine
// key of cert, or the root's when cert is nil (the caller showed the owner
// what it signs).
func SignGrant(a GrantAct, key crypto.Signer, cert []byte, now time.Time) (GrantRequest, error) {
	a.NotAfter = now.Add(OrderLife).UTC()
	body, err := json.Marshal(a)
	if err != nil {
		return GrantRequest{}, err
	}
	var opts crypto.SignerOpts = crypto.SHA256
	if _, ok := key.Public().(ed25519.PublicKey); ok && cert != nil {
		opts = crypto.Hash(0)
	}
	sig, err := crypto.SignMessage(key, rand.Reader, append([]byte(grantPrefix), body...), opts)
	if err != nil {
		return GrantRequest{}, fmt.Errorf("signature: %w", err)
	}
	return GrantRequest{Body: body, Sig: sig, Cert: cert}, nil
}

// GrantEntry is a grant line's part of the issuer's log (Entry.Grant).
type GrantEntry struct {
	ID      string    `json:"id"`
	Who     string    `json:"who,omitempty"`
	Where   string    `json:"where,omitempty"`
	Service string    `json:"service,omitempty"`
	ForS    int64     `json:"for_s,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Digest  string    `json:"digest,omitempty"`
	Serial  string    `json:"serial,omitempty"`
	Until   time.Time `json:"until,omitzero"`
}

type grantReq struct {
	GrantEntry
	name     string // the requester's machine
	key      crypto.PublicKey
	at, void time.Time
	answered string // "", "granted", "denied"
	by       string
}

type grantRec struct {
	GrantEntry
	by      string
	revoked bool
	cert    []byte
}

// grants is the grant part of the issuer's state, replayed from its log.
type grants struct {
	reqs   map[string]*grantReq // by request id
	issued map[string]*grantRec // by serial (hex)
	// cut: the serials the last applied removal revoked, for its trace
	// (traceCut); Open clears them.
	cut []string
}

func (g *grants) init() {
	if g.reqs == nil {
		g.reqs, g.issued = map[string]*grantReq{}, map[string]*grantRec{}
	}
}

func (g *grants) apply(e Entry) error {
	g.init()
	ge := e.Grant
	switch e.Act {
	case ActGrantAsk:
		c, err := x509.ParseCertificate(e.Cert)
		if err != nil {
			return fmt.Errorf("a grant request's certificate: %w", err)
		}
		g.reqs[ge.ID] = &grantReq{GrantEntry: *ge, name: e.Name, key: c.PublicKey, at: e.Time, void: e.NotAfter}
	case ActGrant:
		if r := g.reqs[ge.ID]; r != nil {
			r.answered, r.by = "granted", e.Actor
		}
		g.issued[ge.Serial] = &grantRec{GrantEntry: *ge, by: e.Actor, cert: e.Cert}
	case ActGrantDeny:
		if r := g.reqs[ge.ID]; r != nil {
			r.answered, r.by = "denied", e.Actor
		}
	case ActGrantRevoke:
		if r := g.issued[ge.Serial]; r != nil {
			r.revoked = true
		}
	}
	return nil
}

// revokeOf revokes every grant of who (a removed person, a revoked
// machine: "person:<email>", "machine:<name>") and voids their requests.
func (g *grants) revokeOf(who string) {
	g.init()
	for sn, r := range g.issued {
		if r.Who == who && !r.revoked {
			r.revoked = true
			g.cut = append(g.cut, sn)
		}
	}
	for _, r := range g.reqs {
		if r.Who == who && r.answered == "" {
			r.answered = "void"
		}
	}
}

// revokeApprovedBy revokes every grant person approved (a removed
// approver: People.tla NoGrantOfRemoved, mutant removal-keeps-approvals;
// nfltr docs/decisions/people-layer-2026-11-25.md "Leaver").
func (g *grants) revokeApprovedBy(person string) {
	g.init()
	for sn, r := range g.issued {
		if r.by == person && !r.revoked {
			r.revoked = true
			g.cut = append(g.cut, sn)
		}
	}
}

var grantIDRE = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`) })

// grantSigner is the member machine that signed r (its name and person)
// or "" for the root, or why it is refused: a certificate in the log,
// unexpired, not revoked or retired, whose key signed. Callers hold mu.
func (i *Issuer) grantSigner(r GrantRequest, now time.Time) (name, person string, cert *x509.Certificate, why string) {
	msg := append([]byte(grantPrefix), r.Body...)
	if r.Cert == nil {
		if !verifyRootSig(i.root, msg, r.Sig) {
			return "", "", nil, "not the organisation root's signature"
		}
		return "", "", nil, ""
	}
	c, err := x509.ParseCertificate(r.Cert)
	if err != nil {
		return "", "", nil, "the signer's certificate: " + err.Error()
	}
	sn := hex.EncodeToString(c.SerialNumber.Bytes())
	sum := sha256.Sum256(r.Cert)
	rec := i.certs[sn]
	if rec == nil || rec.digest != hex.EncodeToString(sum[:]) {
		return "", "", nil, "the signer's certificate is not in the issuer's log"
	}
	n := i.names[rec.name]
	switch {
	case !now.Before(rec.notAfter) || n.revoked || n.isRetired(sn):
		return "", "", nil, "the signer's certificate is expired, revoked or retired"
	case !verifyRenewSig(c.PublicKey, msg, r.Sig):
		return "", "", nil, "not signed by the certificate's key"
	}
	return rec.name, n.dev.Person, c, ""
}

// GrantAnswer is what a grant act did: the request it names, the grant
// signed (Serial, Until) for an approval.
type GrantAnswer struct {
	Request string    `json:"request"`
	Serial  string    `json:"serial,omitempty"`
	Until   time.Time `json:"until,omitzero"`
}

// ApplyGrant applies a signed grant act (Grant.tla Request, Sign, Deny,
// Revoke). An approval returns the grant it signed.
func (i *Issuer) ApplyGrant(r GrantRequest, now time.Time) (GrantAnswer, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	name, person, cert, why := i.grantSigner(r, now)
	var a GrantAct
	if why == "" {
		if err := json.Unmarshal(r.Body, &a); err != nil {
			why = "the act: " + err.Error()
		}
	}
	switch {
	case why != "":
	case a.OrgID != i.orgID:
		why = fmt.Sprintf("the act is of organisation %q, not %s", a.OrgID, i.orgID)
	case !now.Before(a.NotAfter) || a.NotAfter.Sub(now) > OrderLife:
		why = "the act is void (until " + a.NotAfter.UTC().Format(time.RFC3339) + ")"
	}
	refusal := Entry{Time: now, Name: name, Actor: person}
	if why != "" {
		return GrantAnswer{}, i.refuse(refusal, why)
	}
	i.grants.init()
	switch a.Act {
	case GrantAsk:
		return i.grantAsk(a, r, name, person, cert, now)
	case GrantApprove, GrantDeny:
		return i.grantAnswer(a, person, cert == nil, now)
	case GrantRevoke:
		return i.grantRevoke(a, person, cert == nil, now)
	}
	return GrantAnswer{}, i.refuse(refusal, "no grant act "+a.Act)
}

// grantAsk logs a request of a member machine (Grant.tla Request): who is
// its person, else the machine. Callers hold mu.
func (i *Issuer) grantAsk(a GrantAct, r GrantRequest, name, person string, cert *x509.Certificate, now time.Time) (GrantAnswer, error) {
	who := orgid.PrincipalOf(orgid.Checked{Name: name, Person: person})
	sum := sha256.Sum256(r.Body)
	e := Entry{Time: now, Act: ActGrantAsk, Name: name, Actor: person, Cert: r.Cert, NotAfter: now.Add(OrderLife),
		Grant: &GrantEntry{ID: a.ID, Who: who, Where: a.Where, Service: a.Service, ForS: a.ForS, Reason: a.Reason, Digest: hex.EncodeToString(sum[:])}}
	for_ := time.Duration(a.ForS) * time.Second
	switch {
	case cert == nil:
		return GrantAnswer{}, i.refuse(e, "a request is a member machine's (its key signs it)")
	case !grantIDRE().MatchString(a.ID) || i.grants.reqs[a.ID] != nil:
		return GrantAnswer{}, i.refuse(e, "the request id is not a new one")
	case !validPlace(a.Where) || a.Service == "" || a.Service == orgid.AnyService || strings.ContainsAny(a.Service, " /:\x00"):
		return GrantAnswer{}, i.refuse(e, fmt.Sprintf("%s/%s is not one service of a machine or a group", a.Where, a.Service))
	case for_ <= 0 || for_ > MaxGrantFor:
		return GrantAnswer{}, i.refuse(e, fmt.Sprintf("a grant is for more than 0 and at most %s", MaxGrantFor))
	case len(a.Reason) > 200:
		return GrantAnswer{}, i.refuse(e, "the reason is longer than 200 bytes")
	}
	if err := i.commit(e); err != nil {
		return GrantAnswer{}, err
	}
	grantLine(map[string]any{"ev": "req", "o": i.orgID, "id": a.ID, "who": who, "where": a.Where, "svc": a.Service, "d": a.ForS, "t": now.Unix()})
	return GrantAnswer{Request: a.ID}, nil
}

func validPlace(s string) bool {
	k, n, ok := strings.Cut(s, ":")
	return ok && n != "" && (k == orgid.KindGroup || k == orgid.KindMachine) && !strings.ContainsAny(n, " /:\x00")
}

// grantAnswer is an approver's approval or denial of a request, or the
// owner's denial (Grant.tla Sign, Deny): the request open, the act over
// its whole body, the signer an approver the root's policy names for its
// service and not the requester. An approval signs the grant: the
// requester's key and principal, the request's service, until now plus the
// request's duration (capped by the issuer certificate's NotAfter).
// Callers hold mu.
func (i *Issuer) grantAnswer(a GrantAct, person string, owner bool, now time.Time) (GrantAnswer, error) {
	req := i.grants.reqs[a.ID]
	act := map[string]string{GrantApprove: ActGrant, GrantDeny: ActGrantDeny}[a.Act]
	e := Entry{Time: now, Act: act, Actor: person, Grant: &GrantEntry{ID: a.ID}}
	if owner {
		e.ActorRole = RoleOwner
	}
	var pol orgid.Policy
	if i.policy != nil {
		pol, _ = orgid.VerifyPolicy(*i.policy, i.root, i.orgID) // taken verified (TakePolicy)
	}
	switch {
	case req == nil:
		return GrantAnswer{}, i.refuse(e, "no such request")
	case req.answered != "": // Grant.tla Sign: ap.id \notin used (issuer-no-replay-set, issuer-signs-denied)
		return GrantAnswer{}, i.refuse(e, "request "+a.ID+" was answered already ("+req.answered+")")
	case !now.Before(req.void):
		return GrantAnswer{}, i.refuse(e, "request "+a.ID+" expired unanswered")
	case a.Digest != req.Digest: // BIND:svc.apprall
		return GrantAnswer{}, i.refuse(e, "the act is not over the request the issuer holds")
	case !(owner && a.Act == GrantDeny) && !pol.Approves(person, req.Where, req.Service): // BIND:svc.apprpol (Grant.tla issuer-any-approver)
		return GrantAnswer{}, i.refuse(e, fmt.Sprintf("%q is not an approver of %s/%s (nfltr access approvers)", person, req.Where, req.Service))
	case !owner && req.Who == orgid.KindPerson+":"+person: // Grant.tla self-approve
		return GrantAnswer{}, i.refuse(e, "an approver never answers their own request")
	case i.names[req.name] == nil || i.names[req.name].revoked:
		return GrantAnswer{}, i.refuse(e, "the requester "+req.name+" is revoked")
	}
	if a.Act == GrantDeny {
		if err := i.commit(e); err != nil {
			return GrantAnswer{}, err
		}
		grantLine(map[string]any{"ev": "deny", "o": i.orgID, "id": a.ID, "by": person, "t": now.Unix()})
		return GrantAnswer{Request: a.ID}, nil
	}
	if err := i.unexpired(now); err != nil {
		return GrantAnswer{}, err
	}
	until := now.Add(time.Duration(req.ForS) * time.Second) // Grant.tla dur-from-request: the request's, never the act's
	if i.cert.NotAfter.Before(until) {
		until = i.cert.NotAfter
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return GrantAnswer{}, err
	}
	serial.SetBit(serial, 126, 1) // positive, 16 bytes: its hex is its log key
	g := orgid.Grant{Request: a.ID, Who: req.Who, Where: req.Where, Service: req.Service, By: person}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, NotBefore: now, NotAfter: until, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{orgid.GrantURI(i.orgID, g)},
	}, i.cert, req.key, i.key)
	if err != nil {
		return GrantAnswer{}, err
	}
	e.Cert = der
	e.Grant = &GrantEntry{ID: a.ID, Who: req.Who, Where: req.Where, Service: req.Service, ForS: req.ForS, Serial: hex.EncodeToString(serial.Bytes()), Until: until}
	if err := i.commit(e); err != nil {
		return GrantAnswer{}, err
	}
	ap := []string{}
	for _, x := range pol.Approvers {
		if x.Where == req.Where && x.Service == req.Service {
			ap = append(ap, x.People...)
		}
	}
	grantLine(map[string]any{"ev": "sign", "o": i.orgID, "id": a.ID, "sn": e.Grant.Serial, "who": req.Who, "where": req.Where, "svc": req.Service,
		"by": person, "ap": ap, "until": until.Unix(), "t": now.Unix()})
	return GrantAnswer{Request: a.ID, Serial: e.Grant.Serial, Until: until}, nil
}

// grantRevoke revokes grant a.ID (its serial): by an approver of its
// service, its holder's person, or the owner (Grant.tla Revoke). It is on
// every CRL from the next until it ends. Callers hold mu.
func (i *Issuer) grantRevoke(a GrantAct, person string, owner bool, now time.Time) (GrantAnswer, error) {
	g := i.grants.issued[a.ID]
	e := Entry{Time: now, Act: ActGrantRevoke, Actor: person, Grant: &GrantEntry{Serial: a.ID}}
	if owner {
		e.ActorRole = RoleOwner
	}
	var pol orgid.Policy
	if i.policy != nil {
		pol, _ = orgid.VerifyPolicy(*i.policy, i.root, i.orgID)
	}
	switch {
	case g == nil:
		return GrantAnswer{}, i.refuse(e, "no such grant")
	case g.revoked:
		return GrantAnswer{}, i.refuse(e, "grant "+a.ID+" is revoked already")
	case !owner && !pol.Approves(person, g.Where, g.Service) && g.Who != orgid.KindPerson+":"+person:
		return GrantAnswer{}, i.refuse(e, fmt.Sprintf("%q may not revoke a grant of %s/%s: an approver of it, its holder or the owner may", person, g.Where, g.Service))
	}
	e.Grant.ID = g.ID
	if err := i.commit(e); err != nil {
		return GrantAnswer{}, err
	}
	grantLine(map[string]any{"ev": "revoke", "o": i.orgID, "sn": a.ID, "t": now.Unix()})
	return GrantAnswer{Request: g.ID, Serial: a.ID, Until: g.Until}, nil
}

// traceCut traces the grants the act just committed revoked with its
// person or machine (Grant.tla Revoke). Callers hold mu.
func (i *Issuer) traceCut(now time.Time) {
	slices.Sort(i.grants.cut)
	for _, sn := range i.grants.cut {
		grantLine(map[string]any{"ev": "revoke", "o": i.orgID, "sn": sn, "t": now.Unix()})
	}
	i.grants.cut = nil
}

// grantSerials are the serials of revoked grants not ended at now, for
// the CRL (Grant.tla RevokeBound). Callers hold mu.
func (i *Issuer) grantSerials(now time.Time) []string {
	var sns []string
	for sn, g := range i.grants.issued {
		if g.revoked && now.Before(g.Until) {
			sns = append(sns, sn)
		}
	}
	slices.Sort(sns)
	return sns
}

// StatusGrantRequest is an open request, for its approvers (nfltr access
// grants, approve, deny): Digest is what an answer signs.
type StatusGrantRequest struct {
	ID      string    `json:"id"`
	Who     string    `json:"who"`
	Where   string    `json:"where"`
	Service string    `json:"service"`
	ForS    int64     `json:"for_s"`
	Reason  string    `json:"reason,omitempty"`
	At      time.Time `json:"at"`
	Void    time.Time `json:"void"`
	Digest  string    `json:"digest"`
}

// StatusGrant is a grant in force: its certificate, which its holder
// presents (client/orgid Identity.ClientCertificate).
type StatusGrant struct {
	Serial  string    `json:"serial"`
	Request string    `json:"request"`
	Who     string    `json:"who"`
	Where   string    `json:"where"`
	Service string    `json:"service"`
	By      string    `json:"by"`
	Until   time.Time `json:"until"`
	Cert    []byte    `json:"cert"`
}

// statusGrants are the open requests and the grants in force at now, at
// most MaxStatusMembers each (more: truncated). Callers hold mu.
func (i *Issuer) statusGrants(now time.Time) (reqs []StatusGrantRequest, gs []StatusGrant, truncated bool) {
	reqs, gs = []StatusGrantRequest{}, []StatusGrant{}
	for _, r := range i.grants.reqs {
		if r.answered == "" && now.Before(r.void) {
			if len(reqs) == MaxStatusMembers {
				truncated = true
				break
			}
			reqs = append(reqs, StatusGrantRequest{ID: r.ID, Who: r.Who, Where: r.Where, Service: r.Service, ForS: r.ForS, Reason: r.Reason, At: r.at, Void: r.void, Digest: r.Digest})
		}
	}
	for _, g := range i.grants.issued {
		if !g.revoked && now.Before(g.Until) {
			if len(gs) == MaxStatusMembers {
				truncated = true
				break
			}
			gs = append(gs, StatusGrant{Serial: g.Serial, Request: g.ID, Who: g.Who, Where: g.Where, Service: g.Service, By: g.by, Until: g.Until, Cert: g.cert})
		}
	}
	slices.SortFunc(reqs, func(a, b StatusGrantRequest) int { return a.At.Compare(b.At) })
	slices.SortFunc(gs, func(a, b StatusGrant) int { return strings.Compare(a.Serial, b.Serial) })
	return reqs, gs, truncated
}
