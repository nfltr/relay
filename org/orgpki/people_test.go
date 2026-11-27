// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// The people layer (people.go; spec/people/People.tla, spec/proverif/people.pv):
// each test names the property it enforces and the planted bug in
// testdata/mutants.txt that makes it fail.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// ownerInvite is the owner's (the root's) invite of email as role.
func (s *signInOrg) ownerInvite(t *testing.T, email, role string) string {
	t.Helper()
	invite, key, err := NewInvite(s.iss.OrgID())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.act(t, s.root, nil, PeopleAct{Act: PeopleInvite, Person: email, Role: role, InviteKey: key}); err != nil {
		t.Fatalf("the owner's invite of %s: %v", email, err)
	}
	return invite
}

// act signs a (by the root when cert is nil, else by key, cert's) and
// applies it.
func (s *signInOrg) act(t *testing.T, key crypto.Signer, cert []byte, a PeopleAct) error {
	t.Helper()
	_, err := s.actRemoval(t, key, cert, a)
	return err
}

func (s *signInOrg) actRemoval(t *testing.T, key crypto.Signer, cert []byte, a PeopleAct) (Removal, error) {
	t.Helper()
	if a.OrgID == "" {
		a.OrgID = s.iss.OrgID()
	}
	if a.Head == "" {
		a.Head = s.iss.Head()
	}
	r, err := SignPeople(a, key, cert, s.now)
	if err != nil {
		t.Fatal(err)
	}
	return s.iss.ApplyPeople(r, s.now)
}

// person is a joined person's first device: its certificate and key.
type person struct {
	email string
	cert  []byte
	key   crypto.Signer
}

// join signs a new device of email in with the invite s holds for it.
func (s *signInOrg) join(t *testing.T, email string) person {
	t.Helper()
	d := newDevice(t)
	der, err := s.enrol(t, d, func(c map[string]any) { c["email"], c["sub"] = email, "sub-"+email })
	if err != nil {
		t.Fatalf("%s's join: %v", email, err)
	}
	return person{email, der, d.ko}
}

// adminInvite is admin a's invite of email as role.
func (s *signInOrg) adminInvite(t *testing.T, a person, email, role string) (string, error) {
	t.Helper()
	invite, key, err := NewInvite(s.iss.OrgID())
	if err != nil {
		t.Fatal(err)
	}
	return invite, s.act(t, a.key, a.cert, PeopleAct{Act: PeopleInvite, Person: email, Role: role, InviteKey: key})
}

func (s *signInOrg) roleOf(email string) string {
	for _, p := range s.iss.People() {
		if p.Email == email && !p.Removed {
			return p.Role
		}
	}
	return ""
}

// People.tla Join, JoinNeedsInvite (mutants idp-alone-enrols,
// invite-unproved; people.pv no-invite, invite-in-clear): a sign-in
// enrols a new person only by an open invite for the token's email,
// proved over the request's keys, once, within InviteLife, with the
// invite's role; the roster survives a replay of the log.
func TestInviteJoinsAPerson(t *testing.T) {
	s := newSignInOrg(t, "alice@example.com")
	d := newDevice(t)
	noInvite := s.request(t, d, s.token(t, d, nil))
	if _, err := s.iss.EnrolSignIn(context.Background(), noInvite, s.now); !errors.Is(err, ErrRefused) {
		t.Fatalf("a sign-in alone: %v, want refused", err)
	}
	invite := s.ownerInvite(t, "alice@example.com", RoleAdmin)
	if s.roleOf("alice@example.com") != "" {
		t.Fatal("an invite put alice in the roster")
	}
	s.now = t0.Add(InviteLife)
	expired := s.request(t, d, s.token(t, d, nil))
	if err := expired.ProveInvite(invite); err != nil {
		t.Fatal(err)
	}
	if _, err := s.iss.EnrolSignIn(context.Background(), expired, s.now); !errors.Is(err, ErrRefused) {
		t.Fatalf("an invite past InviteLife: %v, want refused", err)
	}
	s.now = t0.Add(time.Hour)
	ok := s.request(t, d, s.token(t, d, nil))
	if err := ok.ProveInvite(invite); err != nil {
		t.Fatal(err)
	}
	der, err := s.iss.EnrolSignIn(context.Background(), ok, s.now)
	if err != nil {
		t.Fatal(err)
	}
	if c := parse(t, der); !slices.Equal(c.EmailAddresses, []string{"alice@example.com"}) {
		t.Fatalf("certificate for %v", c.EmailAddresses)
	}
	if r := s.roleOf("alice@example.com"); r != RoleAdmin {
		t.Fatalf("alice's role %q, want the invite's admin", r)
	}
	d2 := newDevice(t)
	again := s.request(t, d2, s.token(t, d2, nil))
	if err := again.ProveInvite(invite); err != nil {
		t.Fatal(err)
	}
	if _, err := s.iss.EnrolSignIn(context.Background(), again, s.now); !errors.Is(err, ErrRefused) {
		t.Fatalf("the invite redeemed twice: %v, want refused", err)
	}
	re, err := Open(s.lines, s.iss.key, s.sink)
	if err != nil {
		t.Fatal(err)
	}
	if ps := re.People(); len(ps) != 1 || ps[0] != (Person{Email: "alice@example.com", Role: RoleAdmin}) {
		t.Fatalf("roster after replay %+v", ps)
	}
}

// People.tla AuthorizedActs, AdminsByOwner (mutants admin-invites-admin,
// admin-changes-role, admin-offboards-admin, no-role-check; people.pv
// queries 3-6 and the re-invite finding): the owner invites any role,
// sets roles and removes anyone; an admin invites and removes members
// only; a member does neither; an invite is for a new person only.
func TestRolesDecideWhoActs(t *testing.T) {
	s := newSignInOrg(t, "alice@example.com")
	s.invites["carol@example.com"] = s.ownerInvite(t, "carol@example.com", RoleAdmin)
	carol := s.join(t, "carol@example.com")
	var err error
	if s.invites["dan@example.com"], err = s.adminInvite(t, carol, "dan@example.com", RoleMember); err != nil {
		t.Fatalf("an admin's invite of a member: %v", err)
	}
	dan := s.join(t, "dan@example.com")
	if _, err := s.adminInvite(t, carol, "eve@example.com", RoleAdmin); !errors.Is(err, ErrRefused) {
		t.Fatalf("an admin's invite of an admin: %v, want refused", err)
	}
	if _, err := s.adminInvite(t, dan, "eve@example.com", RoleMember); !errors.Is(err, ErrRefused) {
		t.Fatalf("a member's invite: %v, want refused", err)
	}
	if _, err := s.adminInvite(t, carol, "dan@example.com", RoleMember); !errors.Is(err, ErrRefused) {
		t.Fatalf("a re-invite of a person in the roster: %v, want refused", err)
	}
	if err := s.act(t, carol.key, carol.cert, PeopleAct{Act: PeopleRole, Person: "dan@example.com", Role: RoleAdmin}); !errors.Is(err, ErrRefused) {
		t.Fatalf("an admin's role change: %v, want refused", err)
	}
	if err := s.act(t, s.root, nil, PeopleAct{Act: PeopleRole, Person: "dan@example.com", Role: RoleAdmin}); err != nil {
		t.Fatalf("the owner's role change: %v", err)
	}
	if err := s.act(t, carol.key, carol.cert, PeopleAct{Act: PeopleRemove, Person: "dan@example.com"}); !errors.Is(err, ErrRefused) {
		t.Fatalf("an admin's removal of an admin: %v, want refused", err)
	}
	if err := s.act(t, s.root, nil, PeopleAct{Act: PeopleRole, Person: "dan@example.com", Role: RoleMember}); err != nil {
		t.Fatal(err)
	}
	if err := s.act(t, carol.key, carol.cert, PeopleAct{Act: PeopleRemove, Person: "dan@example.com"}); err != nil {
		t.Fatalf("an admin's removal of a member: %v", err)
	}
	// carol demoted: her next request is a member's, at once.
	if err := s.act(t, s.root, nil, PeopleAct{Act: PeopleRole, Person: "carol@example.com", Role: RoleMember}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.adminInvite(t, carol, "eve@example.com", RoleMember); !errors.Is(err, ErrRefused) {
		t.Fatalf("a demoted admin's invite: %v, want refused", err)
	}
	var acts []string
	for _, l := range s.lines {
		if e := entryOf(t, l); e.Act == ActInvite || e.Act == ActRole || e.Act == ActRevoked {
			acts = append(acts, e.Act+":"+e.ActorRole+":"+e.Person+":"+e.Role)
		}
	}
	want := []string{"invite:owner:carol@example.com:admin", "invite:admin:dan@example.com:member", "role:owner:dan@example.com:admin",
		"role:owner:dan@example.com:member", "revoked:admin:dan@example.com:member", "role:owner:carol@example.com:member"}
	if !slices.Equal(acts, want) {
		t.Fatalf("the log's people acts\n%v\nwant\n%v", acts, want)
	}
}

// People.tla Offboard, NoOrphan, ReachBound (mutants
// offboard-misses-machine, relay-not-filed, code-outlives-offboard):
// removing a person lists every machine of theirs (a sign-in's and a
// code's) with its relay machine id in the one log line, puts each
// certificate in the next CRL, refuses their renewals, sign-ins, a code
// made before the removal and new codes.
func TestRemovalFilesEveryMachine(t *testing.T) {
	s := newSignInOrg(t, "alice@example.com")
	ana := s.join(t, "ana@example.com")
	mac, mk := s.codeDeviceAt(t, "ana-mac", "ana@example.com", "m-anamac")
	early, err := s.iss.MakeDeviceToken("ana-phone", []string{"web"}, "", Device{Person: "ana@example.com", App: "send"}, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.actRemoval(t, s.root, nil, PeopleAct{Act: PeopleRemove, Person: "ana@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Filed{{Name: "ana-mac", MachineID: "m-anamac"}, {Name: parse(t, ana.cert).Subject.CommonName}}
	if r.Person != "ana@example.com" || !slices.Equal(r.Filed, want) {
		t.Fatalf("removal %+v, want %v", r, want)
	}
	if e := entryOf(t, s.lines[len(s.lines)-1]); e.Act != ActRevoked || !slices.Equal(e.Filed, want) {
		t.Fatalf("the removal's log line %+v", e)
	}
	der, err := s.iss.CRL(s.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range [][]byte{ana.cert, mac} {
		sn := parse(t, c).SerialNumber
		if !slices.ContainsFunc(crl.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool { return e.SerialNumber.Cmp(sn) == 0 }) {
			t.Errorf("%s not in the CRL", parse(t, c).Subject.CommonName)
		}
	}
	if _, _, _, err := renewDaily(t, s.org, mac, mk, t0, t0.Add(time.Hour)); !errors.Is(err, ErrRefused) {
		t.Errorf("a removed person's renewal: %v, want refused", err)
	}
	req, err := NewEnrolRequest(early, csrOf(t, newKey(t), "ana-phone"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.iss.Enrol(req, t0); !errors.Is(err, ErrRefused) {
		t.Errorf("a code made before the removal: %v, want refused", err)
	}
	if _, err := s.iss.MakeDeviceToken("ana-2", []string{"web"}, "", Device{Person: "ana@example.com", App: "send"}, time.Hour, t0); err == nil {
		t.Error("a new code for a removed person")
	}
	if _, err := s.actRemoval(t, s.root, nil, PeopleAct{Act: PeopleRemove, Person: "ana@example.com"}); !errors.Is(err, ErrRefused) {
		t.Errorf("a removal again: %v, want refused", err)
	}
	re, err := Open(s.lines, s.iss.key, s.sink)
	if err != nil {
		t.Fatal(err)
	}
	if ps := re.People(); len(ps) != 1 || !ps[0].Removed {
		t.Fatalf("roster after replay %+v", ps)
	}
}

// codeDeviceAt enrols name for person by the owner's code with a relay
// machine id.
func (s *signInOrg) codeDeviceAt(t *testing.T, name, person, machineID string) ([]byte, crypto.Signer) {
	t.Helper()
	k := newKey(t)
	tok, err := s.iss.MakeDeviceToken(name, []string{"web"}, machineID, Device{Person: person, App: "send"}, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewEnrolRequest(tok, csrOf(t, k, name))
	if err != nil {
		t.Fatal(err)
	}
	der, err := s.iss.Enrol(req, t0)
	if err != nil {
		t.Fatal(err)
	}
	return der, k
}

// people.pv's bindings (BIND:people.*): each row changes one field a relay
// (or an insider) controls in an honest message and requires a refusal.
// `make spec-bindings`.
var peopleBindings = map[string]func(t *testing.T){
	// The issuer certifies a sign-in only with an open invite for the
	// token's person, proved over the request's keys (mutants
	// invite-unproved, idp-alone-enrols).
	"people.invite": func(t *testing.T) {
		s := newSignInOrg(t, "ana@example.com")
		invite := s.ownerInvite(t, "ana@example.com", RoleMember)
		_ = s.ownerInvite(t, "bob@example.com", RoleMember)
		d := newDevice(t)
		honest := func() SignInRequest {
			r := s.request(t, d, s.token(t, d, nil))
			if err := r.ProveInvite(invite); err != nil {
				t.Fatal(err)
			}
			return r
		}
		for what, edit := range map[string]func(*SignInRequest){
			"no proof":              func(r *SignInRequest) { r.Invite = nil },
			"proof over other keys": func(r *SignInRequest) { r.CSR = csrOf(t, newKey(t), "x") },
			"proof by another key":  func(r *SignInRequest) { r.Invite.Sig = slices.Clone(r.Invite.Sig); r.Invite.Sig[0] ^= 1 },
			"another org's proof": func(r *SignInRequest) {
				_, k, _ := parseInvite(invite)
				r.Invite.Sig = signJoin(k, "o-aaaaaaaaaaaaaaaaaaaaaaaaaa", r)
			},
		} {
			r := honest()
			edit(&r)
			if _, err := s.iss.EnrolSignIn(context.Background(), r, s.now); !errors.Is(err, ErrRefused) {
				t.Errorf("%s: %v, want refused", what, err)
			}
		}
		bob := s.request(t, d, s.token(t, d, func(c map[string]any) { c["email"] = "bob@example.com" }))
		if err := bob.ProveInvite(invite); err != nil {
			t.Fatal(err)
		}
		if _, err := s.iss.EnrolSignIn(context.Background(), bob, s.now); !errors.Is(err, ErrRefused) {
			t.Errorf("ana's invite with bob's sign-in: %v, want refused", err)
		}
		if _, err := s.iss.EnrolSignIn(context.Background(), honest(), s.now); err != nil {
			t.Errorf("the honest join: %v", err)
		}
	},
	// The person's role is the invite's, which the inviter signed: a
	// relay's change of it in the act is refused (mutant role-from-request).
	"people.role": func(t *testing.T) {
		s := newSignInOrg(t, "ana@example.com")
		_, key, err := NewInvite(s.iss.OrgID())
		if err != nil {
			t.Fatal(err)
		}
		r, err := SignPeople(PeopleAct{OrgID: s.iss.OrgID(), Head: s.iss.Head(), Act: PeopleInvite, Person: "ana@example.com", Role: RoleMember, InviteKey: key}, s.root, nil, s.now)
		if err != nil {
			t.Fatal(err)
		}
		r.Body = []byte(strings.Replace(string(r.Body), `"role":"member"`, `"role":"admin"`, 1))
		if _, err := s.iss.ApplyPeople(r, s.now); !errors.Is(err, ErrRefused) {
			t.Errorf("the invite's role changed: %v, want refused", err)
		}
		s.invites["ana@example.com"] = s.ownerInvite(t, "ana@example.com", RoleMember)
		s.join(t, "ana@example.com")
		if got := s.roleOf("ana@example.com"); got != RoleMember {
			t.Errorf("ana's role %q, want the invite's member", got)
		}
	},
	// An admin's request is signed by the key of a certificate the issuer
	// signed for a person whose role in the log is admin (mutants
	// no-role-check, admin-sig-unchecked, admin-cert-unchecked).
	"people.admin": func(t *testing.T) {
		s := newSignInOrg(t, "ana@example.com")
		s.invites["carol@example.com"] = s.ownerInvite(t, "carol@example.com", RoleAdmin)
		carol := s.join(t, "carol@example.com")
		dan := s.join(t, "dan@example.com")
		forged := forgeCert(t, carol.cert)
		_, key, _ := NewInvite(s.iss.OrgID())
		honest, err := SignPeople(PeopleAct{OrgID: s.iss.OrgID(), Head: s.iss.Head(), Act: PeopleInvite, Person: "eve@example.com", Role: RoleMember, InviteKey: key}, carol.key, carol.cert, s.now)
		if err != nil {
			t.Fatal(err)
		}
		member, err := SignPeople(PeopleAct{OrgID: s.iss.OrgID(), Head: s.iss.Head(), Act: PeopleInvite, Person: "eve@example.com", Role: RoleMember, InviteKey: key}, dan.key, dan.cert, s.now)
		if err != nil {
			t.Fatal(err)
		}
		for what, r := range map[string]PeopleRequest{
			"a member's request":           member,
			"a member's certificate":       {Body: honest.Body, Sig: honest.Sig, Cert: dan.cert},
			"another key's signature":      {Body: honest.Body, Sig: mustSign(t, newKey(t), honest.Body), Cert: carol.cert},
			"a certificate not the issuer": {Body: honest.Body, Sig: honest.Sig, Cert: forged},
			"no signature":                 {Body: honest.Body, Cert: carol.cert},
		} {
			if _, err := s.iss.ApplyPeople(r, s.now); !errors.Is(err, ErrRefused) {
				t.Errorf("%s: %v, want refused", what, err)
			}
		}
		if _, err := s.iss.ApplyPeople(honest, s.now); err != nil {
			t.Errorf("the honest request: %v", err)
		}
	},
	// An act names the log's head after the roster's last change: the
	// relay's replay of an applied act, after another act, and an act
	// naming a head the log never had are refused (mutant act-no-head;
	// lane SECFIX, review S7).
	"people.head": func(t *testing.T) {
		s := newSignInOrg(t, "ana@example.com")
		s.join(t, "dan@example.com")
		sign := func(role string) PeopleRequest {
			r, err := SignPeople(PeopleAct{OrgID: s.iss.OrgID(), Head: s.iss.Head(), Act: PeopleRole, Person: "dan@example.com", Role: role}, s.root, nil, s.now)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		promote := sign(RoleAdmin)
		if _, err := s.iss.ApplyPeople(promote, s.now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.iss.ApplyPeople(sign(RoleMember), s.now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.iss.ApplyPeople(promote, s.now); !errors.Is(err, ErrRefused) {
			t.Errorf("the promotion replayed after the demotion: %v, want refused", err)
		}
		reopened, err := Open(s.lines, s.iss.key, s.sink) // the roster's last change from the log
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reopened.ApplyPeople(promote, s.now); !errors.Is(err, ErrRefused) {
			t.Errorf("the promotion replayed to the reopened issuer: %v, want refused", err)
		}
		if got := s.roleOf("dan@example.com"); got != RoleMember {
			t.Errorf("dan is %q, want member", got)
		}
		other, err := SignPeople(PeopleAct{OrgID: s.iss.OrgID(), Head: strings.Repeat("0", 64), Act: PeopleRole, Person: "dan@example.com", Role: RoleAdmin}, s.root, nil, s.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.iss.ApplyPeople(other, s.now); !errors.Is(err, ErrRefused) {
			t.Errorf("a head the log never had: %v, want refused", err)
		}
	},
	// The issuer refuses a removed person's join, renewal, sign-in again
	// and admin request (mutants admin-after-offboard, rejoin-old-invite;
	// people.pv no-deny).
	"people.removed": func(t *testing.T) {
		s := newSignInOrg(t, "ana@example.com")
		s.invites["carol@example.com"] = s.ownerInvite(t, "carol@example.com", RoleAdmin)
		carol := s.join(t, "carol@example.com")
		if err := s.act(t, s.root, nil, PeopleAct{Act: PeopleRemove, Person: "carol@example.com"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.adminInvite(t, carol, "eve@example.com", RoleMember); !errors.Is(err, ErrRefused) {
			t.Errorf("a removed admin's request: %v, want refused", err)
		}
		if _, _, _, err := renewDaily(t, s.org, carol.cert, carol.key, t0, t0.Add(time.Hour)); !errors.Is(err, ErrRefused) {
			t.Errorf("a removed person's renewal: %v, want refused", err)
		}
		if _, err := s.enrol(t, newDevice(t), func(c map[string]any) { c["email"] = "carol@example.com" }); !errors.Is(err, ErrRefused) {
			t.Errorf("a removed person's join: %v, want refused", err)
		}
		if err := s.act(t, s.root, nil, PeopleAct{Act: PeopleInvite, Person: "carol@example.com", Role: RoleMember, InviteKey: newKey(t).Public().(ed25519.PublicKey)}); !errors.Is(err, ErrRefused) {
			t.Errorf("a removed person invited again: %v, want refused", err)
		}
	},
}

// TestPeopleModelBindings runs every row; each is a BIND id of people.pv.
func TestPeopleModelBindings(t *testing.T) {
	src, err := os.ReadFile("../../spec/proverif/people.pv")
	if err != nil {
		t.Fatal(err)
	}
	for id, row := range peopleBindings {
		if !strings.Contains(string(src), "BIND:"+id+" ") {
			t.Errorf("people.pv declares no BIND:%s", id)
		}
		t.Run(id, row)
	}
}

// forgeCert is a copy of der's certificate signed by another key: the
// same subject, serial and key.
func forgeCert(t *testing.T, der []byte) []byte {
	t.Helper()
	c := parse(t, der)
	k := newKey(t)
	parent := *c
	parent.PublicKey = k.Public()
	f, err := x509.CreateCertificate(rand.Reader, c, &parent, c.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// entryOf is a log line's entry.
func entryOf(t *testing.T, line []byte) Entry {
	t.Helper()
	var e Entry
	if err := json.Unmarshal(line, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

// signJoin is the invite's proof over r's keys for organisation orgID.
func signJoin(k ed25519.PrivateKey, orgID string, r *SignInRequest) []byte {
	return ed25519.Sign(k, joinMessage(orgID, r.CSR, r.RelayKey))
}

// mustSign is k's signature over a people act's body.
func mustSign(t *testing.T, k ed25519.PrivateKey, body []byte) []byte {
	t.Helper()
	return ed25519.Sign(k, append([]byte(peoplePrefix), body...))
}
