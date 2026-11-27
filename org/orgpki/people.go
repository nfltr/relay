// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The people layer (nfltr docs/decisions/people-layer-2026-11-25.md;
// spec/people/People.tla, spec/proverif/people.pv): a person joins by an
// invite, has a role (owner, admin, member) and is removed in one act. The
// roster is the issuer's log: an invite line, the join (the issued line
// naming the invite and its role), role lines and the removal (a revoked
// line naming the person). The owner is the root: its acts are the root's
// signature. An admin's act is signed by the key of one of the admin's
// machines; the issuer checks the admin's role in its log at each request,
// so a role change takes effect at once. The IdP's sign-in only
// authenticates a join; it never enrols anyone by itself.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The roles. The owner is the root holder, one per organisation, never in
// the roster's rows: it leaves only by moving the root.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// InviteLife is how long an invite can be redeemed (owner decision
// 2026-11-25: 7 days).
const InviteLife = 7 * 24 * time.Hour

// The acts of a PeopleAct.
const (
	PeopleInvite = "invite"
	PeopleRole   = "role"
	PeopleRemove = "remove"
)

// allowed is People.tla's Allowed: the owner anything; an admin invites
// and removes members only. Joining and adding one's own machine need no
// role (they are not PeopleActs).
func allowed(actorRole, act, subjectRole string) bool {
	return actorRole == RoleOwner ||
		actorRole == RoleAdmin && (act == PeopleInvite || act == PeopleRemove) && subjectRole == RoleMember
}

type personRec struct {
	role    string
	removed bool
}

type inviteRec struct {
	person, role string
	expires      time.Time
	used         bool
}

// roster is the people part of the issuer's state, replayed from its log.
type roster struct {
	people  map[string]*personRec // by email
	invites map[string]*inviteRec // by id (the invite key, base64url)
}

func (r *roster) init() {
	if r.people == nil {
		r.people, r.invites = map[string]*personRec{}, map[string]*inviteRec{}
	}
}

func (r *roster) apply(e Entry) {
	r.init()
	switch e.Act {
	case ActInvite:
		r.invites[e.Invite] = &inviteRec{person: e.Person, role: e.Role, expires: e.NotAfter}
	case ActRole:
		if p := r.people[e.Person]; p != nil {
			p.role = e.Role
		}
	}
}

// joined applies an issued line that redeemed an invite.
func (r *roster) joined(e Entry) {
	if e.Act != ActIssued || e.Invite == "" {
		return
	}
	r.init()
	r.people[e.Person] = &personRec{role: e.Role}
	if inv := r.invites[e.Invite]; inv != nil {
		inv.used = true
	}
}

func (r *roster) removed(person string) {
	if p := r.people[person]; p != nil {
		p.removed = true
	}
}

// openInvite is the person's invite not redeemed and not expired, if any.
func (r *roster) openInvite(person string, now time.Time) bool {
	for _, inv := range r.invites {
		if inv.person == person && !inv.used && now.Before(inv.expires) {
			return true
		}
	}
	return false
}

// Person is one row of the roster.
type Person struct {
	Email   string `json:"email"`
	Role    string `json:"role"`
	Removed bool   `json:"removed,omitempty"`
}

// People is the roster, by email.
func (i *Issuer) People() []Person {
	i.mu.Lock()
	defer i.mu.Unlock()
	var ps []Person
	for email, p := range i.roster.people {
		ps = append(ps, Person{Email: email, Role: p.role, Removed: p.removed})
	}
	slices.SortFunc(ps, func(a, b Person) int { return strings.Compare(a.Email, b.Email) })
	return ps
}

// An invite is invitePrefix<org id>.<seed>: the seed of an Ed25519 key
// the inviter made. The issuer's log holds only its public key (the
// invite's id), so neither the relay that carries the invite act nor the
// log's readers can redeem it; the person's device proves the seed over
// the keys it enrols (InviteProof), never sending it.
const invitePrefix = "nfltr-org-invite-v1." // #nosec G101 -- the invite format prefix, not a credential

// NewInvite makes an invite for the organisation orgID: the string the
// person pastes into nfltr join, and its public key for the invite act.
func NewInvite(orgID string) (invite string, key ed25519.PublicKey, err error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", nil, err
	}
	return invitePrefix + orgID + "." + base64.RawURLEncoding.EncodeToString(seed),
		ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

func parseInvite(invite string) (orgID string, key ed25519.PrivateKey, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(invite), invitePrefix)
	orgID, s, _ := strings.Cut(rest, ".")
	seed, derr := base64.RawURLEncoding.Strict().DecodeString(s)
	if !ok || derr != nil || len(seed) != ed25519.SeedSize || !validOrgID(orgID) {
		return "", nil, errors.New("not an nfltr organisation invite")
	}
	return orgID, ed25519.NewKeyFromSeed(seed), nil
}

// InviteOrgID is the organisation an invite is for (its mailboxes).
func InviteOrgID(invite string) (string, error) {
	orgID, _, err := parseInvite(invite)
	return orgID, err
}

func inviteID(key []byte) string { return base64.RawURLEncoding.EncodeToString(key) }

// InviteProof is a join's proof of its invite: the invite's public key and
// its signature over the organisation and the request's two keys
// (BIND:people.invite).
type InviteProof struct {
	Key []byte `json:"key"`
	Sig []byte `json:"sig"`
}

func joinMessage(orgID string, csr, relayKey []byte) []byte {
	return []byte("nfltr-org-join-v1\x00" + orgID + "\x00" + string(csr) + "\x00" + string(relayKey))
}

// ProveInvite makes r a join: the invite's proof over r's keys.
func (r *SignInRequest) ProveInvite(invite string) error {
	orgID, k, err := parseInvite(invite)
	if err != nil {
		return err
	}
	r.Invite = &InviteProof{Key: k.Public().(ed25519.PublicKey), Sig: ed25519.Sign(k, joinMessage(orgID, r.CSR, r.RelayKey))}
	return nil
}

// checkInvite is the join's invite, or why not (People.tla Join,
// JoinNeedsInvite; people.pv IssuerJoin): an invite in the log for the
// token's person, open, unexpired, proved over the request's keys, and
// the person new to the roster. Callers hold mu.
func (i *Issuer) checkInvite(req SignInRequest, person string, now time.Time) (*inviteRec, string) {
	if req.Invite == nil {
		return nil, "an invite is needed: a sign-in alone enrols no one (nfltr people invite)"
	}
	id := inviteID(req.Invite.Key)
	inv := i.roster.invites[id]
	switch {
	case inv == nil:
		return nil, "no such invite"
	case len(req.Invite.Key) != ed25519.PublicKeySize || !ed25519.Verify(req.Invite.Key, joinMessage(i.orgID, req.CSR, req.RelayKey), req.Invite.Sig):
		return nil, "the invite is not proved over the request's keys"
	case inv.used:
		return nil, "the invite was redeemed already"
	case !now.Before(inv.expires):
		return nil, "the invite expired"
	case inv.person != person:
		return nil, "the invite is for " + inv.person + ", not " + person
	case i.roster.people[person] != nil:
		return nil, person + " is in the organisation already"
	}
	return inv, ""
}

// PeopleAct is an act on the roster: invite Person with Role (InviteKey:
// NewInvite's key), set Person's Role, or remove Person.
type PeopleAct struct {
	OrgID     string    `json:"org_id"`
	Act       string    `json:"act"`
	Person    string    `json:"person"`
	Role      string    `json:"role,omitempty"`
	InviteKey []byte    `json:"invite_key,omitempty"`
	NotAfter  time.Time `json:"not_after"`
	// Head is the issuer log's head the signer read (Status.Head): the
	// issuer takes the act only when no roster change came after it, so
	// an applied act sent again is refused (BIND:people.head; lane
	// SECFIX, review S7).
	Head string `json:"head"`
}

// PeopleRequest is a PeopleAct's JSON bytes signed over the prefix
// "nfltr-org-people-v1" NUL and them: by the root (the owner; no Cert) or by the key of Cert, a
// certificate of one of an admin's machines (BIND:people.admin). The
// relay carries it and can withhold or replay it; a replay is refused
// (PeopleAct.Head).
type PeopleRequest struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
	Cert []byte `json:"cert,omitempty"`
}

const peoplePrefix = "nfltr-org-people-v1\x00"

// SignPeople signs a, void OrderLife after now: by the root when cert is
// nil (the caller showed the owner what it signs), else by the key of
// cert (an admin's machine).
func SignPeople(a PeopleAct, key crypto.Signer, cert []byte, now time.Time) (PeopleRequest, error) {
	a.NotAfter = now.Add(OrderLife).UTC()
	body, err := json.Marshal(a)
	if err != nil {
		return PeopleRequest{}, err
	}
	var opts crypto.SignerOpts = crypto.SHA256
	if _, ok := key.Public().(ed25519.PublicKey); ok && cert != nil {
		opts = crypto.Hash(0)
	}
	sig, err := crypto.SignMessage(key, rand.Reader, append([]byte(peoplePrefix), body...), opts)
	if err != nil {
		return PeopleRequest{}, fmt.Errorf("signature: %w", err)
	}
	return PeopleRequest{Body: body, Sig: sig, Cert: cert}, nil
}

// Filed is one machine of a removed person: its certificate is listed in
// the next CRL, the relay's revoke of MachineID (when the name has one)
// and the rotation of the addresses Name serves are filed for the relay
// and the name's keeper (People.tla Offboard, ReachBound).
type Filed struct {
	Name      string `json:"name"`
	MachineID string `json:"machine_id,omitempty"`
}

// Removal is what a person's removal did: every machine of theirs.
type Removal struct {
	Person string  `json:"person"`
	Filed  []Filed `json:"filed"`
}

// ApplyPeople applies a signed PeopleAct: the signer's role in the log
// now allows it (People.tla AuthorizedActs). A removal returns what it
// filed.
func (i *Issuer) ApplyPeople(r PeopleRequest, now time.Time) (Removal, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	by, role, why := i.signer(r, now)
	var a PeopleAct
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
	case i.heads[a.Head] < i.rosterLine || i.heads[a.Head] == 0:
		why = "the act names a head before the roster's last change (sent again, or signed before another act): sign it again against the current status"
	}
	if why != "" {
		return Removal{}, i.refuse(Entry{Time: now, Actor: by, ActorRole: role}, why)
	}
	d, err := Device{Person: a.Person}.valid()
	if err != nil || d.Person == "" {
		return Removal{}, i.refuse(Entry{Time: now, Actor: by, ActorRole: role}, fmt.Sprintf("person %q: %v", a.Person, err))
	}
	switch a.Act {
	case PeopleInvite:
		return Removal{}, i.invite(by, role, d.Person, a.Role, a.InviteKey, now)
	case PeopleRole:
		return Removal{}, i.setRole(by, role, d.Person, a.Role, now)
	case PeopleRemove:
		return i.removePerson(by, role, d.Person, now)
	}
	return Removal{}, i.refuse(Entry{Time: now, Actor: by, ActorRole: role}, "no act "+a.Act)
}

// rosterChange is a log line that changes the roster: an invite, a role,
// a person's removal. A people act signed at a head before it is refused
// (PeopleAct.Head).
func rosterChange(e Entry) bool {
	return e.Act == ActInvite || e.Act == ActRole || e.Act == ActRevoked && e.Person != ""
}

// signer is who signed r and their role in the log now ("" and owner for
// the root), or why it is refused (people.pv IssuerInvite, IssuerOff:
// BIND:people.admin, BIND:people.removed). Callers hold mu.
func (i *Issuer) signer(r PeopleRequest, now time.Time) (by, role, why string) {
	msg := append([]byte(peoplePrefix), r.Body...)
	if r.Cert == nil {
		if !verifyRootSig(i.root, msg, r.Sig) {
			return "", "", "not the organisation root's signature"
		}
		return "", RoleOwner, ""
	}
	c, err := x509.ParseCertificate(r.Cert)
	if err != nil {
		return "", "", "the signer's certificate: " + err.Error()
	}
	sn := hex.EncodeToString(c.SerialNumber.Bytes())
	sum := sha256.Sum256(r.Cert)
	rec := i.certs[sn]
	if rec == nil || rec.digest != hex.EncodeToString(sum[:]) {
		return "", "", "the signer's certificate is not in the issuer's log"
	}
	n := i.names[rec.name]
	switch {
	case !now.Before(rec.notAfter) || n.revoked || n.isRetired(sn):
		return "", "", "the signer's certificate is expired, revoked or retired"
	case !verifyRenewSig(c.PublicKey, msg, r.Sig):
		return "", "", "not signed by the certificate's key"
	}
	p := i.roster.people[n.dev.Person]
	if p == nil || p.removed { // people.pv admin-after-offboard
		return n.dev.Person, "", n.dev.Person + " is not in the organisation"
	}
	return n.dev.Person, p.role, ""
}

// invite logs an invite for a person new to the roster (people-layer
// finding 1: an invite never changes a person's role). Callers hold mu.
func (i *Issuer) invite(by, actorRole, person, role string, key []byte, now time.Time) error {
	e := Entry{Time: now, Act: ActInvite, Person: person, Role: role, Actor: by, ActorRole: actorRole}
	switch {
	case role != RoleAdmin && role != RoleMember:
		return i.refuse(e, "an invite is for an admin or a member")
	case !allowed(actorRole, PeopleInvite, role):
		return i.refuse(e, actorRole+" may not invite an "+role)
	case len(key) != ed25519.PublicKeySize || i.roster.invites[inviteID(key)] != nil:
		return i.refuse(e, "the invite key is not a new Ed25519 key")
	case i.roster.people[person] != nil || i.deniedDev(Device{Person: person}):
		return i.refuse(e, person+" is or was in the organisation: an invite is for a new person")
	case i.roster.openInvite(person, now):
		return i.refuse(e, person+" has an open invite")
	}
	e.Invite, e.NotAfter = inviteID(key), now.Add(InviteLife)
	return i.commit(e)
}

// setRole is the owner's: an active person's role. Callers hold mu.
func (i *Issuer) setRole(by, actorRole, person, role string, now time.Time) error {
	e := Entry{Time: now, Act: ActRole, Person: person, Role: role, Actor: by, ActorRole: actorRole}
	p := i.roster.people[person]
	switch {
	case !allowed(actorRole, PeopleRole, role):
		return i.refuse(e, actorRole+" may not change roles")
	case role != RoleAdmin && role != RoleMember:
		return i.refuse(e, "a role is admin or member")
	case p == nil || p.removed:
		return i.refuse(e, person+" is not in the organisation")
	case p.role == role:
		return i.refuse(e, person+" is "+role+" already")
	}
	return i.commit(e)
}

// removePerson removes a person in one act (People.tla Offboard): the
// roster row, every name of theirs revoked (listed in the next CRL), each
// one's relay revoke and address rotation filed in the same line, their
// invites and codes void (deniedDev at redemption). A person not in the
// roster (a device an owner's code enrolled for them) only the owner
// removes. Callers hold mu.
func (i *Issuer) removePerson(by, actorRole, person string, now time.Time) (Removal, error) {
	e := Entry{Time: now, Act: ActRevoked, Person: person, Actor: by, ActorRole: actorRole}
	p := i.roster.people[person]
	subject := RoleMember
	if p != nil {
		subject = p.role
	}
	e.Role = subject
	switch {
	case p == nil && actorRole != RoleOwner, p != nil && p.removed, i.deniedDev(Device{Person: person}):
		return Removal{}, i.refuse(e, person+" is not in the organisation")
	case !allowed(actorRole, PeopleRemove, subject):
		return Removal{}, i.refuse(e, actorRole+" may not remove an "+subject)
	}
	for name, n := range i.names {
		if n.dev.Person == person && !n.revoked {
			e.Filed = append(e.Filed, Filed{Name: name, MachineID: n.machineID})
		}
	}
	slices.SortFunc(e.Filed, func(a, b Filed) int { return strings.Compare(a.Name, b.Name) })
	if err := i.commit(e); err != nil {
		return Removal{}, err
	}
	i.traceRevoked(Device{Person: person}, now)
	return Removal{Person: person, Filed: e.Filed}, nil
}

// RevokePerson is the owner's removal of person on the issuer's machine
// (AppEnrol.tla RevokeUser, People.tla Offboard; mutants
// revoke-user-one-name, sso-skips-deny): every name of theirs revoked and
// filed in one log line (the Removal), their enrolments refused from now,
// a code made before included.
func (i *Issuer) RevokePerson(person string, now time.Time) (Removal, error) {
	d, err := Device{Person: person}.valid()
	if err != nil || d.Person == "" {
		return Removal{}, fmt.Errorf("person %q: %v", person, err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.removePerson("", RoleOwner, d.Person, now)
}

// RevokeApp revokes every name enrolled for app, whoever's, and refuses
// its enrolments from now (AppEnrol.tla RevokeApp; mutant
// revoke-app-sso-only).
func (i *Issuer) RevokeApp(app string, now time.Time) error {
	if err := ValidLabel("app", app); err != nil {
		return err
	}
	d := Device{App: app}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.deniedDev(d) {
		return fmt.Errorf("%s is revoked already", app)
	}
	if err := i.commit(Entry{Time: now, Act: ActRevoked, App: app}); err != nil {
		return err
	}
	i.traceRevoked(d, now)
	return nil
}

func (i *Issuer) traceRevoked(d Device, now time.Time) {
	i.traceCut(now)
	names := []string{}
	for name, n := range i.names {
		if n.dev.of(d.Person, d.App) && n.revoked {
			traceLine(map[string]any{"ev": "revoke", "o": i.orgID, "n": name, "t": now.Unix()})
			names = append(names, name)
		}
	}
	appTraceLine(map[string]any{"ev": "revoke", "o": i.orgID, "u": d.Person, "a": d.App, "names": names, "t": now.Unix()})
}

func denyKey(person, app string) string {
	if person != "" {
		return "person:" + person
	}
	return "app:" + app
}

// of: d is person's (person != "") or app's.
func (d Device) of(person, app string) bool {
	return person != "" && d.Person == person || app != "" && d.App == app
}

func (i *Issuer) deniedDev(d Device) bool {
	return d.Person != "" && i.denied[denyKey(d.Person, "")] || d.App != "" && i.denied[denyKey("", d.App)]
}
