// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// ErrRefused wraps every refusal of the issuer (a token, an enrolment, a
// renewal); the log holds a refused entry for it.
var ErrRefused = errors.New("refused")

// ErrIssuerExpired: the issuer certificate is past its NotAfter, so the
// issuer signs no certificate and no CRL (members refuse both) until
// nfltr org issuer renew installs a new one.
var ErrIssuerExpired = errors.New("the issuer certificate expired")

// A token is tokenPrefix<org id>.<token id>.<secret>: the org id (public)
// names the organisation's mailboxes, which keep the first root's id
// across a rotation, so a machine pinned on the current root finds them.
// v1 tokens (nfltr until v2.1.57) carried no org id.
const (
	tokenPrefix   = "nfltr-org-token-v2." // #nosec G101 -- the token format prefix, not a credential
	tokenPrefixV1 = "nfltr-org-token-v1." // #nosec G101 -- the old format's prefix, refused by name
)

// Sink stores one log line durably before the issuer acts on it (the
// caller's append-only file).
type Sink func(line []byte) error

// EnrolRequest is a machine's first request: its CSR, the token's id and
// HMAC(token, CSR). The relay that carries it never sees the token and
// cannot attach another key to it (enrol.pv query 5, mutant
// token-in-request).
type EnrolRequest struct {
	TokenID string `json:"token_id"`
	CSR     []byte `json:"csr"`
	MAC     []byte `json:"mac"`
	// MachineID, when set, is the joining machine's relay machine id,
	// MachineMAC the token's MAC over it and the CSR (NewEnrolRequestFor;
	// BIND:enrol.id): the issuer binds it into a certificate whose token
	// names no id (a login bundle's) when the move policy admits it
	// (spec/enrol/Join.tla JoinedBound). An issuer before it ignores both.
	MachineID  string `json:"machine_id,omitempty"`
	MachineMAC []byte `json:"machine_mac,omitempty"`
}

// RenewRequest is a renewal: the current certificate, a CSR for a new key,
// and the current key's signature over that CSR.
type RenewRequest struct {
	Cert []byte `json:"cert"`
	CSR  []byte `json:"csr"`
	Sig  []byte `json:"sig"`
	// MachineID, when set, asks to move the name to this relay machine id
	// (NewMoveRequest: the machine enrolled with the relay again); Sig is
	// then over it too (enrol.pv query 20, BIND:move.id).
	MachineID string `json:"machine_id,omitempty"`
}

type tokenRec struct {
	name      string
	groups    []string
	machineID string
	dev       Device
	expires   time.Time
	rebind    bool // MakeRebindToken's: moves an enrolled name to machineID
	void      bool // made before a restore from a backup (restore.go)
}

type certRec struct {
	name, key, digest string
	from              string // the serial it renewed ("" an enrolment)
	token             string // the token an enrolment redeemed; "" for a renewal
	notAfter          time.Time
}

type nameRec struct {
	groups    []string
	machineID string
	dev       Device
	revoked   bool
	serials   []string  // in issue order
	retired   int       // serials[:retired]: retired by a rebind (the name's earlier machine id), listed in every CRL until they expire
	authUntil time.Time // enrolled by sign-in: renews by itself until then (AuthLife); zero: by a code, until revoked
}

// Issuer is the organisation's automated signer: every act takes its one
// lock, is written to the log (Sink) and only then takes effect.
type Issuer struct {
	mu         sync.Mutex
	orgID      string
	root       *x509.Certificate
	recovery   *x509.Certificate
	rootLabel  string
	rootKind   string
	cert       *x509.Certificate
	key        ed25519.PrivateKey
	tokenKey   []byte
	tokens     map[string]*tokenRec
	names      map[string]*nameRec
	denied     map[string]bool     // "person:<address>", "app:<app>": revoked (RevokePerson, RevokeApp)
	certs      map[string]*certRec // by serial (hex)
	crlNumber  int64
	crlNext    time.Time
	crlDue     bool                 // a revocation or a new issuer certificate since the last CRL
	movedTo    string               // the receive key the log's last fence names (move.go)
	restoredAt time.Time            // the last restore from a backup (restore.go); zero: none
	carried    map[string]time.Time // serials a restore took from the published CRL, listed until then
	head       string
	heads      map[string]bool       // every head the log had: a remote renewal checkpoints one (renew.go)
	rules      map[string]SignInRule // by id (signin.go)
	roster     roster                // people, roles and invites (people.go)
	policy     *orgid.SignedPolicy   // the root's newest access policy (policy.go); nil: none
	policyNum  int64
	grants     grants // requests and grants (grant.go)
	idps       providers
	sink       Sink
	move       MovePolicy // nil: no move without a rebind token
}

// MovePolicy admits moving name to the relay machine id: nil when id is
// a machine of the issuer's own relay account by that name (Enrol.tla
// Move, MoveOnlyOwnAccount). The relay answers it, so it is never the
// only check: the request is signed by the name's key over the id.
type MovePolicy func(name, machineID string) error

// SetMovePolicy lets a renewal move its name to a new relay machine id
// when p admits it (nil: only a rebind token moves a name).
func (i *Issuer) SetMovePolicy(p MovePolicy) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.move = p
}

// The kinds of root primary. An organisation has one, recorded in its init
// line and kept by every rotation.
const (
	RootSecureEnclave = "secure-enclave" // the owner's Mac, Touch ID per signature
	RootFile          = "file"           // a passphrase-encrypted file, the passphrase per signature
)

// Genesis is a new organisation's first two log lines: the root and the
// recovery's certificates (and the root's kind and label), then the
// issuer's.
func Genesis(root, recovery *x509.Certificate, rootLabel, rootKind string, issuer *x509.Certificate, now time.Time) ([][]byte, error) {
	l1, err := encode(Entry{Time: now, Act: ActInit, Cert: root.Raw, Recovery: recovery.Raw, KeyLabel: rootLabel, RootKind: rootKind}, "")
	if err != nil {
		return nil, err
	}
	l2, err := encode(Entry{Time: now, Act: ActIssuer, Cert: issuer.Raw}, lineHash(l1))
	if err != nil {
		return nil, err
	}
	return [][]byte{l1, l2}, nil
}

// Open replays a verified log into an issuer holding key, the private key
// of the log's current issuer certificate.
func Open(lines [][]byte, key ed25519.PrivateKey, sink Sink) (*Issuer, error) {
	entries, head, err := VerifyLog(lines)
	if err != nil {
		return nil, err
	}
	i := &Issuer{tokens: map[string]*tokenRec{}, names: map[string]*nameRec{}, certs: map[string]*certRec{}, heads: map[string]bool{}, rules: map[string]SignInRule{}, sink: sink}
	for _, l := range lines {
		i.heads[lineHash(l)] = true
	}
	for _, e := range entries {
		if err := i.apply(e); err != nil {
			return nil, err
		}
	}
	i.head = head
	i.grants.cut = nil // replayed: no act of this run
	if i.cert == nil {
		return nil, errors.New("the log names no issuer under the current root")
	}
	if err := i.useKey(key); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *Issuer) useKey(key ed25519.PrivateKey) error {
	if pub, ok := i.cert.PublicKey.(ed25519.PublicKey); !ok || !pub.Equal(key.Public()) {
		return errors.New("the issuer key is not the one the log's issuer certificate names")
	}
	tk, err := hkdf.Key(sha256.New, key.Seed(), nil, "nfltr-org-token-key-v1", 32)
	if err != nil {
		return err
	}
	i.key, i.tokenKey = key, tk
	return nil
}

func (i *Issuer) apply(e Entry) error {
	switch e.Act {
	case ActInit:
		root, err := x509.ParseCertificate(e.Cert)
		if err != nil {
			return err
		}
		if i.recovery, err = x509.ParseCertificate(e.Recovery); err != nil {
			return err
		}
		i.root, i.rootLabel, i.rootKind = root, e.KeyLabel, e.RootKind
		i.orgID, err = orgid.OrgIDOfRoot(root)
		return err
	case ActRotated:
		root, err := x509.ParseCertificate(e.Cert)
		i.root, i.rootLabel, i.cert = root, e.KeyLabel, nil
		return err
	case ActIssuer:
		c, err := x509.ParseCertificate(e.Cert)
		i.cert, i.crlDue = c, true
		return err
	case ActToken:
		i.tokens[e.Token] = &tokenRec{name: e.Name, groups: e.Groups, machineID: e.MachineID, dev: Device{e.Person, e.App}, expires: e.NotAfter, rebind: e.Rebind}
	case ActIssued, ActRenewed, ActRebound, ActAdopted:
		n := i.names[e.Name]
		if n == nil {
			n = &nameRec{groups: e.Groups, machineID: e.MachineID, dev: Device{e.Person, e.App}}
			i.names[e.Name] = n
		}
		if e.Act == ActRebound { // Enrol.tla Rebind: one entry certifies the new id and retires the rest
			n.retired, n.machineID, i.crlDue = len(n.serials), e.MachineID, true
		}
		n.serials = append(n.serials, e.Serial)
		i.roster.joined(e) // people.go: a join by invite
		if !e.AuthUntil.IsZero() {
			n.authUntil = e.AuthUntil
		}
		i.certs[e.Serial] = &certRec{name: e.Name, key: e.Key, digest: e.Digest, token: e.Token, notAfter: e.NotAfter, from: e.From}
	case ActRevoked:
		if n := i.names[e.Name]; n != nil {
			n.revoked = true
			i.grants.revokeOf(orgid.KindMachine + ":" + e.Name) // its grants with it (grant.go)
		}
		if e.Person != "" {
			i.grants.revokeOf(orgid.KindPerson + ":" + e.Person) // a removed person's grants (lead decision 2026-11-26)
		}
		if e.Person != "" || e.App != "" {
			if i.denied == nil {
				i.denied = map[string]bool{}
			}
			i.denied[denyKey(e.Person, e.App)] = true
			i.roster.removed(e.Person)
			for name, n := range i.names {
				if n.dev.of(e.Person, e.App) {
					n.revoked = true
					i.grants.revokeOf(orgid.KindMachine + ":" + name)
				}
			}
		}
		i.crlDue = true
	case ActInvite, ActRole:
		i.roster.apply(e)
	case ActRule:
		if e.Rule == nil {
			return errors.New("a rule line names no rule")
		}
		i.rules[e.Rule.ID] = *e.Rule
	case ActRuleRemoved:
		delete(i.rules, e.Name)
	case ActPolicy: // a CRL with it, so the members read the status carrying it at the push
		i.policy, i.policyNum, i.crlDue = &orgid.SignedPolicy{Body: e.Policy, Sig: e.RootSig}, e.Number, true
	case ActGrantAsk, ActGrant, ActGrantDeny, ActGrantRevoke:
		if e.Grant == nil {
			return errors.New("a grant line names no grant")
		}
		if e.Act == ActGrant || e.Act == ActGrantRevoke { // a CRL with it: the push wakes the members' read of the status carrying it
			i.crlDue = true
		}
		return i.grants.apply(e)
	case ActCRL:
		i.crlNumber, i.crlNext, i.crlDue = e.Number, e.NotAfter, false
	case ActRestored:
		i.applyRestored(e)
	case ActMoved:
		i.movedTo = e.Key
	case ActArrived:
		i.movedTo = ""
	}
	return nil
}

// commit writes e to the log, then applies it. Callers hold mu.
func (i *Issuer) commit(e Entry) error {
	if err := i.refuseMoved(e); err != nil {
		return err
	}
	line, err := encode(e, i.head)
	if err != nil {
		return err
	}
	if err := i.sink(line); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	prev := i.head
	i.head = lineHash(line)
	i.heads[i.head] = true
	traceCommit(i.orgID, e, prev, i.head)
	return i.apply(e)
}

// refuse logs a refusal and returns it.
func (i *Issuer) refuse(e Entry, reason string) error {
	e.Act, e.Reason = ActRefused, reason
	err := fmt.Errorf("%w: %s", ErrRefused, reason)
	if lerr := i.commit(e); lerr != nil {
		return errors.Join(err, lerr)
	}
	return err
}

// RootKind is the root primary's kind. A log of v2.1.57 names none: its
// root was the Secure Enclave, the only kind then.
func (i *Issuer) RootKind() string {
	if i.rootKind == "" {
		return RootSecureEnclave
	}
	return i.rootKind
}

// OrgID, Root, Recovery, Cert, RootLabel and Head describe the issuer's
// organisation as its log has it.
func (i *Issuer) OrgID() string                { return i.orgID }
func (i *Issuer) Root() *x509.Certificate      { return i.root }
func (i *Issuer) Recovery() *x509.Certificate  { return i.recovery }
func (i *Issuer) Cert() *x509.Certificate      { return i.cert }
func (i *Issuer) RootLabel() string            { return i.rootLabel }
func (i *Issuer) Groups() []string             { return slices.Clone(i.cert.Subject.OrganizationalUnit) }
func (i *Issuer) Head() string                 { i.mu.Lock(); defer i.mu.Unlock(); return i.head }
func (i *Issuer) tokenSecret(id string) []byte { return mac(i.tokenKey, "token\x00"+id) }

func mac(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func enrolMAC(secret, csr []byte) []byte { return mac(secret, "nfltr-org-enrol-v1\x00"+string(csr)) }
func renewMessage(csr []byte) []byte     { return append([]byte("nfltr-org-renew-v1\x00"), csr...) }

// enrolIDMAC is the token's MAC over a join's relay machine id and its
// CSR (BIND:enrol.id).
func enrolIDMAC(secret []byte, machineID string, csr []byte) []byte {
	return mac(secret, "nfltr-org-enrol-id-v1\x00"+machineID+"\x00"+string(csr))
}

// moveMessage is what a move's signature covers: the new relay machine id
// and the CSR (BIND:move.id).
func moveMessage(csr []byte, machineID string) []byte {
	return append([]byte("nfltr-org-move-v1\x00"+machineID+"\x00"), csr...)
}

// TokenName is the name the token id was made for, "" for none.
func (i *Issuer) TokenName(id string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	if t := i.tokens[id]; t != nil {
		return t.name
	}
	return ""
}

// MakeToken makes a single-use bootstrap token for a name not enrolled,
// bound to its groups (within the issuer's policy) and, when given, the
// machine id; it lasts ttl.
func (i *Issuer) MakeToken(name string, groups []string, machineID string, ttl time.Duration, now time.Time) (string, error) {
	return i.MakeDeviceToken(name, groups, machineID, Device{}, ttl, now)
}

// MakeDeviceToken is MakeToken for an app's device enrolled for a person
// (the admin code of spec/appenrol/AppEnrol.tla): the certificate, and
// every renewal of it, names dev's person and app.
func (i *Issuer) MakeDeviceToken(name string, groups []string, machineID string, dev Device, ttl time.Duration, now time.Time) (string, error) {
	dev, err := dev.valid()
	if err != nil {
		return "", err
	}
	if err := ValidLabel("name", name); err != nil {
		return "", err
	}
	if err := validGroups(groups); err != nil {
		return "", err
	}
	if err := validMachineID(machineID); err != nil {
		return "", err
	}
	if ttl <= 0 || ttl > IssuerLife {
		return "", fmt.Errorf("token lifetime %s: more than 0 and at most %s", ttl, IssuerLife)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if policy := i.Groups(); !subset(groups, policy) {
		return "", fmt.Errorf("%w: groups %v are not all in the issuer's policy %v", ErrRefused, groups, policy)
	}
	if i.names[name] != nil {
		return "", fmt.Errorf("%w: %s is enrolled already; a token is for a new name", ErrRefused, name)
	}
	if i.deniedDev(dev) {
		return "", fmt.Errorf("%w: %s or %s is revoked", ErrRefused, dev.Person, dev.App)
	}
	return i.newToken(Entry{Time: now, Act: ActToken, Name: name, Groups: slices.Clone(groups), MachineID: machineID, Person: dev.Person, App: dev.App, NotAfter: now.Add(ttl)})
}

// MakeRebindToken makes a single-use rebind token: it moves name, enrolled
// and not revoked, to machineID (a new relay machine id) with its groups
// (nfltr docs/decisions/org-rebind-2026-11-17.md; RFC 7030
// simplereenroll, authorised by the operator's token, not the old
// certificate). The machine of that id redeems it with Enrol; the answer
// retires every earlier serial of the name (Enrol.tla Rebind). To the
// name's own machine id it is a reissue (nfltr
// docs/decisions/org-reissue-2026-11-22.md): only while the name holds no
// valid certificate (Enrol.tla ReissueRetiresOnlyExpired), checked again
// at its redemption.
func (i *Issuer) MakeRebindToken(name, machineID string, ttl time.Duration, now time.Time) (string, error) {
	if err := ValidLabel("name", name); err != nil {
		return "", err
	}
	if err := validMachineID(machineID); err != nil || machineID == "" {
		return "", fmt.Errorf("a rebind names the new machine id: %q: %v", machineID, err)
	}
	if ttl <= 0 || ttl > IssuerLife {
		return "", fmt.Errorf("token lifetime %s: more than 0 and at most %s", ttl, IssuerLife)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	n := i.names[name]
	switch {
	case n == nil:
		return "", fmt.Errorf("%w: %s is not enrolled; a rebind token is for an enrolled name (nfltr org token for a new one)", ErrRefused, name)
	case n.revoked:
		return "", fmt.Errorf("%w: %s is revoked", ErrRefused, name)
	case n.machineID == machineID && !i.validUntil(n, now).IsZero():
		return "", fmt.Errorf("%w: %s has machine id %s already and a certificate valid until %s: a rebind to its own machine id (a reissue) is for a name whose certificates all expired", ErrRefused, name, machineID, i.validUntil(n, now).UTC().Format(time.RFC3339))
	case !n.authUntil.IsZero():
		return "", fmt.Errorf("%w: %s was enrolled by sign-in: it signs in again", ErrRefused, name)
	}
	return i.newToken(Entry{Time: now, Act: ActToken, Name: name, Groups: slices.Clone(n.groups), MachineID: machineID, Person: n.dev.Person, App: n.dev.App, NotAfter: now.Add(ttl), Rebind: true})
}

// newToken commits e (an ActToken entry) under a fresh token id and
// returns the token. Callers hold mu.
func (i *Issuer) newToken(e Entry) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	e.Token = base64.RawURLEncoding.EncodeToString(raw)
	if err := i.commit(e); err != nil {
		return "", err
	}
	return tokenPrefix + i.orgID + "." + e.Token + "." + base64.RawURLEncoding.EncodeToString(i.tokenSecret(e.Token)), nil
}

// parseToken splits a token into its organisation's id, its id and its
// secret.
func parseToken(token string) (orgID, id string, secret []byte, err error) {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(token, tokenPrefixV1) {
		return "", "", nil, errors.New("an nfltr organisation token of the v1 format (before v2.1.58), which names no organisation: ask the organisation's owner for a new token (nfltr org token)")
	}
	rest, ok := strings.CutPrefix(token, tokenPrefix)
	parts := strings.Split(rest, ".")
	if ok && len(parts) == 3 {
		orgID, id = parts[0], parts[1]
		secret, err = base64.RawURLEncoding.Strict().DecodeString(parts[2])
	}
	if !ok || len(parts) != 3 || err != nil || !validOrgID(orgID) || id == "" || len(secret) != sha256.Size {
		return "", "", nil, errors.New("not an nfltr organisation token")
	}
	return orgID, id, secret, nil
}

// validOrgID: OrgID's form, "o-" and 26 lower-case base32 characters.
func validOrgID(id string) bool {
	rest, ok := strings.CutPrefix(id, "o-")
	sum, err := b32.DecodeString(strings.ToUpper(rest))
	return ok && err == nil && len(sum) == 16 && rest == strings.ToLower(rest)
}

// TokenOrgID is the id of the organisation a token is for: it names the
// organisation's mailboxes (EnrolMailbox and the rest), nothing more. The
// root a machine takes is the one it was given the fingerprint of.
func TokenOrgID(token string) (string, error) {
	orgID, _, _, err := parseToken(token)
	return orgID, err
}

// NewEnrolRequest is the machine's side: the request for csr under token.
func NewEnrolRequest(token string, csr []byte) (EnrolRequest, error) {
	_, id, secret, err := parseToken(token)
	if err != nil {
		return EnrolRequest{}, err
	}
	return EnrolRequest{TokenID: id, CSR: csr, MAC: enrolMAC(secret, csr)}, nil
}

// NewEnrolRequestFor is NewEnrolRequest stating this machine's relay
// machine id (none when ""), under the token's MAC.
func NewEnrolRequestFor(token string, csr []byte, machineID string) (EnrolRequest, error) {
	r, err := NewEnrolRequest(token, csr)
	if err != nil || machineID == "" {
		return r, err
	}
	_, _, secret, err := parseToken(token)
	if err != nil {
		return EnrolRequest{}, err
	}
	r.MachineID, r.MachineMAC = machineID, enrolIDMAC(secret, machineID, csr)
	return r, nil
}

// NewRenewRequest is the machine's side of a renewal: csr for its new key,
// signed with its current key.
func NewRenewRequest(cert []byte, current ed25519.PrivateKey, csr []byte) RenewRequest {
	return RenewRequest{Cert: cert, CSR: csr, Sig: ed25519.Sign(current, renewMessage(csr))}
}

// NewMoveRequest is NewRenewRequest asking to move the name to the relay
// machine id (its machine enrolled with the relay again), signed over it.
func NewMoveRequest(cert []byte, current ed25519.PrivateKey, csr []byte, machineID string) RenewRequest {
	return RenewRequest{Cert: cert, CSR: csr, MachineID: machineID, Sig: ed25519.Sign(current, moveMessage(csr, machineID))}
}

// parseCSR: a CSR its key signed (proof of possession), for an Ed25519 key
// or (a device's key in a Secure Enclave or TPM) a P-256 one.
// The issuer takes only its key: the name and groups are the token's or
// the log's (enrol.pv mutant name-from-request).
func parseCSR(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	switch k := csr.PublicKey.(type) {
	case ed25519.PublicKey:
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("the key is not Ed25519 or P-256")
		}
	default:
		return nil, errors.New("the key is not Ed25519 or P-256")
	}
	return csr, nil
}

// Enrol redeems a token: the certificate carries the token's name, groups
// and machine id, never the request's. A token certifies one key: asked
// again for the key it enrolled (its answer was lost, or came after the
// join gave up), it is answered again with a new certificate of that key,
// while the name is not revoked and was not renewed since; any other key
// is refused (spec/enrol/Join.tla Issue, mutants burn-name,
// reissue-any-key, reissue-revoked, reissue-after-renewal).
func (i *Issuer) Enrol(req EnrolRequest, now time.Time) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	refusal := Entry{Time: now, Token: req.TokenID}
	t := i.tokens[req.TokenID]
	if t == nil {
		return nil, i.refuse(refusal, "unknown token")
	}
	refusal.Name = t.name
	if t.void { // OrgMove.tla Revive (mutant revive-keeps-tokens): the lost issuer may have redeemed it
		return nil, i.refuse(refusal, "the token was made before the issuer was restored from a backup: make a new one")
	}
	if !hmac.Equal(req.MAC, enrolMAC(i.tokenSecret(req.TokenID), req.CSR)) {
		return nil, i.refuse(refusal, "the request is not bound to the token")
	}
	if req.MachineID != "" || req.MachineMAC != nil { // Join.tla Relabel: the relay cannot state an id
		if !hmac.Equal(req.MachineMAC, enrolIDMAC(i.tokenSecret(req.TokenID), req.MachineID, req.CSR)) {
			return nil, i.refuse(refusal, "the request's relay machine id is not bound to the token")
		}
	}
	if !now.Before(t.expires) {
		return nil, i.refuse(refusal, "the token expired")
	}
	if i.deniedDev(t.dev) { // AppEnrol.tla RevokedUserCut: a code made before the revoke
		return nil, i.refuse(refusal, "the token's person or app is revoked")
	}
	cr, err := parseCSR(req.CSR)
	if err != nil {
		return nil, i.refuse(refusal, "CSR: "+err.Error())
	}
	pub := cr.PublicKey.(ed25519.PublicKey)
	if t.rebind {
		return i.rebind(t, req.TokenID, pub, refusal, now)
	}
	// A token is for a name not enrolled, so after its first redemption
	// it answers only the key it enrolled (enrol.pv 5, 6).
	if n := i.names[t.name]; n != nil {
		last := i.certs[n.serials[len(n.serials)-1]]
		if n.revoked || last.token != req.TokenID || last.key != orgid.KeyFingerprint(pub) {
			traceLine(map[string]any{"ev": "refuse", "o": i.orgID, "n": t.name, "from": "", "tok": req.TokenID, "k": orgid.KeyFingerprint(pub), "why": "enrolled", "t": now.Unix()})
			return nil, i.refuse(refusal, t.name+" is enrolled already (the token was redeemed, or another token's was)")
		}
	}
	der, err := i.issue(ActIssued, t.name, t.groups, i.enrolMachineID(t, req.MachineID), t.dev, pub, req.TokenID, "", now)
	if err == nil {
		appTraceLine(map[string]any{"ev": "code", "o": i.orgID, "n": t.name, "u": t.dev.Person, "a": t.dev.App, "tok": req.TokenID, "k": orgid.KeyFingerprint(pub), "t": now.Unix()})
	}
	return der, err
}

// enrolMachineID is the relay machine id an enrolment certifies: the
// token's, or, for a token naming none, the one the request stated when
// the move policy admits it (Join.tla Issue, BindOnlyOwnAccount); else
// none, as before (the keeper moves the name later if the policy admits
// it then). Callers hold mu.
func (i *Issuer) enrolMachineID(t *tokenRec, stated string) string {
	if t.machineID != "" || stated == "" || i.move == nil || validMachineID(stated) != nil {
		return t.machineID
	}
	if err := i.move(t.name, stated); err != nil {
		return ""
	}
	return stated
}

// rebind redeems a rebind token (Enrol.tla Rebind, enrol.pv query 11):
// the certificate carries the token's name, groups and new machine id; its
// first redemption retires every earlier serial of the name in the same
// log entry. Asked again for the key it rebound (a lost answer), the token
// is answered again as an enrolment token is (Join.tla Issue); any other
// key, a revoked name, or a name rebound by another token since is
// refused. Callers hold mu.
func (i *Issuer) rebind(t *tokenRec, tokenID string, pub ed25519.PublicKey, refusal Entry, now time.Time) ([]byte, error) {
	n := i.names[t.name]
	if n == nil || n.revoked {
		return nil, i.refuse(refusal, t.name+" is not enrolled or is revoked")
	}
	redeemed := slices.ContainsFunc(n.serials, func(sn string) bool { return i.certs[sn].token == tokenID })
	if redeemed {
		last := i.certs[n.serials[len(n.serials)-1]]
		if last.token != tokenID || last.key != orgid.KeyFingerprint(pub) {
			traceLine(map[string]any{"ev": "refuse", "o": i.orgID, "n": t.name, "from": "", "tok": tokenID, "k": orgid.KeyFingerprint(pub), "why": "enrolled", "t": now.Unix()})
			return nil, i.refuse(refusal, "the rebind token was redeemed")
		}
		return i.issue(ActIssued, t.name, t.groups, t.machineID, t.dev, pub, tokenID, "", now)
	}
	same := t.machineID == n.machineID
	if until := i.validUntil(n, now); same && !until.IsZero() { // Enrol.tla ReissueRetiresOnlyExpired (mutant reissue-while-valid)
		return nil, i.refuse(refusal, t.name+" holds a certificate valid until "+until.UTC().Format(time.RFC3339)+": a reissue to its own machine id is for a name whose certificates all expired")
	}
	der, err := i.issue(ActRebound, t.name, t.groups, t.machineID, t.dev, pub, tokenID, "", now)
	if err == nil {
		traceLine(map[string]any{"ev": "rebind", "o": i.orgID, "n": t.name, "s": n.serials[len(n.serials)-1], "same": same, "t": now.Unix()})
	}
	return der, err
}

// validUntil is the latest NotAfter of n's serials a rebind did not
// retire that is after now; zero when none is valid (Enrol.tla
// NoValidCert). Callers hold mu.
func (i *Issuer) validUntil(n *nameRec, now time.Time) time.Time {
	var until time.Time
	for _, sn := range n.serials[n.retired:] {
		if na := i.certs[sn].notAfter; now.Before(na) && na.After(until) {
			until = na
		}
	}
	return until
}

// isRetired: serial sn of n was retired by a rebind.
func (n *nameRec) isRetired(sn string) bool {
	k := slices.Index(n.serials, sn)
	return k >= 0 && k < n.retired
}

// Renew re-certifies a machine under the current issuer for a new key. It
// takes only a certificate its own log holds (Enrol.tla renew-forged), not
// expired, or the name's newest within RenewGrace after its NotAfter
// (Enrol.tla Renews: renew-past-grace, grace-any-serial), or one asked
// again within it for the key its newest successor renewed it for (Enrol.tla Repeat), of a name not
// revoked (renew-revoked), with the current key's signature over the CSR.
func (i *Issuer) Renew(req RenewRequest, now time.Time) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	refusal := Entry{Time: now}
	cur, err := x509.ParseCertificate(req.Cert)
	if err != nil {
		return nil, i.refuse(refusal, "certificate: "+err.Error())
	}
	sn := hex.EncodeToString(cur.SerialNumber.Bytes())
	refusal.Serial = sn
	if until, ok := i.carried[sn]; ok && now.Before(until) { // OrgMove.tla Revive: revoked in the CRL a restore took
		i.traceRefused(sn, cur, "revoked", now)
		return nil, i.refuse(refusal, "the certificate is revoked (in the published CRL the issuer's restore took)")
	}
	rec := i.certs[sn]
	if n, ok := i.adoptable(cur); rec == nil && ok {
		if err := i.adopt(cur, req.Cert, n, now); err != nil {
			return nil, err
		}
		rec = i.certs[sn]
	}
	sum := sha256.Sum256(req.Cert)
	if rec == nil || rec.digest != hex.EncodeToString(sum[:]) {
		i.traceRefused(sn, cur, "log", now)
		return nil, i.refuse(refusal, "the certificate is not in the issuer's log")
	}
	refusal.Name = rec.name
	n := i.names[rec.name]
	if !now.Before(rec.notAfter) && (!now.Before(rec.notAfter.Add(RenewGrace)) || !i.newestKey(n, rec) && !i.askedAgain(n, sn, req.CSR, now)) {
		i.traceRefused(sn, cur, "expired", now)
		return nil, i.refuse(refusal, fmt.Sprintf("the certificate expired at %s, more than %s ago or superseded by a newer one; the organisation's owner reissues the name (nfltr org token --rebind %s --machine-id %s), then nfltr org join on the machine", rec.notAfter.UTC().Format(time.RFC3339), RenewGrace, rec.name, n.machineID))
	}
	if n.revoked {
		i.traceRefused(sn, cur, "revoked", now)
		return nil, i.refuse(refusal, rec.name+" is revoked")
	}
	if n.isRetired(sn) { // Enrol.tla NoRenewOfRetired (mutant renew-rebound): the old machine id's disk
		i.traceRefused(sn, cur, "rebound", now)
		return nil, i.refuse(refusal, rec.name+" moved to another machine id (rebind): this certificate is retired")
	}
	if !n.authUntil.IsZero() && now.After(n.authUntil) { // AppEnrol.tla Renew (mutant renew-ignores-auth)
		i.traceRefused(sn, cur, "other", now)
		appTraceLine(map[string]any{"ev": "refuse", "o": i.orgID, "n": rec.name, "why": "auth", "t": now.Unix()})
		refusal.Reason = ErrSignInEnded.Error()
		refusal.Act = ActRefused
		if err := i.commit(refusal); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrRefused, ErrSignInEnded)
	}
	msg := renewMessage(req.CSR)
	if req.MachineID != "" {
		msg = moveMessage(req.CSR, req.MachineID)
	}
	if !verifyRenewSig(cur.PublicKey, msg, req.Sig) {
		i.traceRefused(sn, cur, "other", now)
		return nil, i.refuse(refusal, "not signed by the certificate's key")
	}
	cr, err := parseCSR(req.CSR)
	if err != nil {
		i.traceRefused(sn, cur, "other", now)
		return nil, i.refuse(refusal, "CSR: "+err.Error())
	}
	if req.MachineID != "" && req.MachineID != n.machineID {
		return i.moveName(rec.name, n, req.MachineID, cr.PublicKey, sn, refusal, now)
	}
	der, err := i.issue(ActRenewed, rec.name, n.groups, n.machineID, n.dev, cr.PublicKey, "", sn, now)
	if err == nil {
		appTraceLine(map[string]any{"ev": "renew", "o": i.orgID, "n": rec.name, "u": n.dev.Person, "a": n.dev.App, "k": orgid.KeyFingerprint(cr.PublicKey), "t": now.Unix()})
	}
	return der, err
}

// askedAgain: the name's newest serial renewed sn for the key of csr,
// which the CSR's signature proves the asker holds, and is still valid or
// in the grace: the machine asked again for an answer it never took (late,
// lost, or its process ended first), so it is answered again (Enrol.tla
// Repeat, mutants no-repeat, repeat-any-key; lane CANARYCERT). Callers
// hold mu.
func (i *Issuer) askedAgain(n *nameRec, sn string, csr []byte, now time.Time) bool {
	newest := i.certs[n.serials[len(n.serials)-1]]
	if newest == nil || newest.from != sn || !now.Before(newest.notAfter.Add(RenewGrace)) {
		return false
	}
	cr, err := parseCSR(csr)
	return err == nil && orgid.KeyFingerprint(cr.PublicKey) == newest.key
}

// newestKey reports whether rec's key is the key of its name's newest
// serial: the newest itself, or a sibling the issuer answered the same
// request with twice (a backlog of the request and its retry, after an
// outage), which the machine took (Enrol.tla NewestKey, mutant
// grace-newest-serial; lane ORGRENEW). A revoked or rebound name is refused
// after this check. Callers hold mu.
func (i *Issuer) newestKey(n *nameRec, rec *certRec) bool {
	newest := i.certs[n.serials[len(n.serials)-1]]
	return newest != nil && newest.key == rec.key
}

// moveName moves name to the relay machine id its key asked for (Enrol.tla
// Move): only when the move policy admits id (MoveOnlyOwnAccount), in one
// rebound entry, as a rebind token's. Callers hold mu.
// ponytail: the policy (a relay call) runs under the issuer's lock; the
// issuer serves one request at a time anyway.
func (i *Issuer) moveName(name string, n *nameRec, id string, pub crypto.PublicKey, from string, refusal Entry, now time.Time) ([]byte, error) {
	if err := validMachineID(id); err != nil {
		return nil, i.refuse(refusal, err.Error())
	}
	if i.move == nil {
		return nil, i.refuse(refusal, "this issuer moves "+name+" to another relay machine only with a rebind token (nfltr org token --rebind)")
	}
	if err := i.move(name, id); err != nil {
		return nil, i.refuse(refusal, fmt.Sprintf("%s does not move to relay machine %s: %v (on the issuer's machine: nfltr org token --rebind %s --machine-id %s)", name, id, err, name, id))
	}
	der, err := i.issue(ActRebound, name, n.groups, id, n.dev, pub, "", from, now)
	if err == nil {
		traceLine(map[string]any{"ev": "rebind", "o": i.orgID, "n": name, "s": n.serials[len(n.serials)-1], "t": now.Unix()})
	}
	return der, err
}

// verifyRenewSig: sig is pub's over msg (Ed25519, or P-256 ECDSA over its
// SHA-256).
func verifyRenewSig(pub crypto.PublicKey, msg, sig []byte) bool {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, msg, sig)
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, sum[:], sig)
	}
	return false
}

func (i *Issuer) issue(act, name string, groups []string, machineID string, dev Device, pub crypto.PublicKey, token, from string, now time.Time) ([]byte, error) {
	return i.issueEntry(act, name, groups, machineID, dev, pub, token, from, now, nil)
}

// issueEntry is issue with more of the log line (extra, when not nil:
// a sign-in's).
func (i *Issuer) issueEntry(act, name string, groups []string, machineID string, dev Device, pub crypto.PublicKey, token, from string, now time.Time, extra func(*Entry)) ([]byte, error) {
	if !subset(groups, i.cert.Subject.OrganizationalUnit) {
		return nil, i.refuse(Entry{Time: now, Name: name, Token: token, Serial: from}, fmt.Sprintf("groups %v are outside the issuer's policy", groups))
	}
	if err := i.unexpired(now); err != nil {
		return nil, err
	}
	t, err := machineTemplate(i.orgID, name, groups, machineID, dev, i.cert, now)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, t, i.cert, pub, i.key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	e := Entry{Time: now, Act: act, Name: name, Groups: slices.Clone(groups), MachineID: machineID, Person: dev.Person, App: dev.App,
		Serial: hex.EncodeToString(t.SerialNumber.Bytes()), From: from, Key: orgid.KeyFingerprint(pub),
		Digest: hex.EncodeToString(sum[:]), Token: token, NotAfter: t.NotAfter}
	if extra != nil {
		extra(&e)
	}
	if err := i.commit(e); err != nil {
		return nil, err
	}
	traceLine(map[string]any{"ev": "issue", "o": i.orgID, "n": name, "s": e.Serial, "from": from, "tok": token, "k": e.Key, "exp": t.NotAfter.Unix(), "t": now.Unix()})
	return der, nil
}

// traceRefused records a refused renewal of serial sn (Enrol.tla Issue's
// checks: why is log, expired or revoked, or other for a reason outside
// the model: a signature, the CSR).
func (i *Issuer) traceRefused(sn string, cur *x509.Certificate, why string, now time.Time) {
	traceLine(map[string]any{"ev": "refuse", "o": i.orgID, "n": cur.Subject.CommonName, "from": sn, "why": why, "t": now.Unix()})
}

// Revoke revokes a name: no renewal from now, and every unexpired serial
// of it in the next CRL.
func (i *Issuer) Revoke(name string, now time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.revokeName(name, now)
}

// revokeName is Revoke with i.mu held.
func (i *Issuer) revokeName(name string, now time.Time) error {
	switch n := i.names[name]; {
	case n == nil:
		return fmt.Errorf("%s is not enrolled", name)
	case n.revoked:
		return fmt.Errorf("%s is revoked already", name)
	}
	if err := i.commit(Entry{Time: now, Act: ActRevoked, Name: name}); err != nil {
		return err
	}
	traceLine(map[string]any{"ev": "revoke", "o": i.orgID, "n": name, "t": now.Unix()})
	appTraceLine(map[string]any{"ev": "revoke", "o": i.orgID, "u": "", "a": "", "names": []string{name}, "t": now.Unix()})
	i.traceCut(now)
	return nil
}

// CRL signs the issuer's next CRL: a higher Number, NextUpdate CRLLife
// on, every unexpired serial of every revoked name (Enrol.tla
// revoke-current-only: a renewed machine's earlier certificate is still
// valid until its NotAfter). Past the issuer certificate's NotAfter it is
// ErrIssuerExpired: members refuse that CRL (orgid.Verifier.TakeCRL).
func (i *Issuer) CRL(now time.Time) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.unexpired(now); err != nil {
		return nil, err
	}
	var listed []x509.RevocationListEntry
	seen := map[string]bool{}
	for _, n := range i.names {
		sns := n.serials[:n.retired] // Enrol.tla Rebind (mutant rebind-keeps-serials)
		if n.revoked {
			sns = n.serials
		}
		for _, sn := range sns {
			if !now.Before(i.certs[sn].notAfter) {
				continue
			}
			seen[sn] = true
			b, _ := hex.DecodeString(sn)
			listed = append(listed, x509.RevocationListEntry{SerialNumber: new(big.Int).SetBytes(b), RevocationTime: now})
		}
	}
	grantSNs := i.grantSerials(now)                                       // Grant.tla Publish: every revoked grant until it ends (RevokeBound)
	for _, sn := range append(i.carriedSerials(seen, now), grantSNs...) { // OrgMove.tla Revive (mutant merge-skipped)
		b, _ := hex.DecodeString(sn)
		listed = append(listed, x509.RevocationListEntry{SerialNumber: new(big.Int).SetBytes(b), RevocationTime: now})
	}
	slices.SortFunc(listed, func(a, b x509.RevocationListEntry) int { return a.SerialNumber.Cmp(b.SerialNumber) })
	number := i.crlNumber + 1
	next := now.Add(CRLLife)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: now, NextUpdate: next, RevokedCertificateEntries: listed,
	}, i.cert, i.key)
	if err != nil {
		return nil, err
	}
	if err := i.commit(Entry{Time: now, Act: ActCRL, Number: number, NotAfter: next}); err != nil {
		return nil, err
	}
	rev := []string{}
	for _, e := range listed {
		rev = append(rev, hex.EncodeToString(e.SerialNumber.Bytes()))
	}
	traceLine(map[string]any{"ev": "crl", "o": i.orgID, "num": number, "next": next.Unix(), "t": now.Unix(), "rev": rev})
	grantLine(map[string]any{"ev": "crl", "o": i.orgID, "num": number, "next": next.Unix(), "t": now.Unix(), "rev": append([]string{}, grantSNs...)})
	return der, nil
}

// unexpired is ErrIssuerExpired past the issuer certificate's NotAfter.
// Callers hold mu.
func (i *Issuer) unexpired(now time.Time) error {
	if !now.Before(i.cert.NotAfter) {
		return fmt.Errorf("%w at %s: nfltr org issuer renew", ErrIssuerExpired, i.cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// checkpoint signs the head with the issuer and the root primary. Callers
// hold mu.
func (i *Issuer) checkpoint(root crypto.Signer, now time.Time) error {
	sig, err := signCheckpoint(root, i.orgID, i.head)
	if err != nil {
		return fmt.Errorf("root signature: %w", err)
	}
	return i.commit(Entry{Time: now, Act: ActCheckpoint, Head: i.head, RootSig: sig,
		IssuerSig: ed25519.Sign(i.key, checkpointMessage(i.orgID, i.head))})
}

// RenewIssuer has the root primary certify the issuer's key again for
// IssuerLife under groups, then sign the log's head: two signatures.
func (i *Issuer) RenewIssuer(root crypto.Signer, groups []string, now time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	c, err := CertifyIssuer(i.root, root, i.key.Public().(ed25519.PublicKey), groups, now)
	if err != nil {
		return err
	}
	if err := i.commit(Entry{Time: now, Act: ActIssuer, Cert: c.Raw}); err != nil {
		return err
	}
	return i.checkpoint(root, now)
}

// Rotate moves the organisation to a new root primary: cross is the
// recovery key's certificate of it (CrossSign), newRoot its signer and
// newKey the new issuer's key, which the new root certifies for groups.
// Machines then renew into the new issuer (Renew, by serials of this log).
func (i *Issuer) Rotate(cross *x509.Certificate, label string, newRoot crypto.Signer, newKey ed25519.PrivateKey, groups []string, now time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := checkRotation(cross, i.recovery, i.root); err != nil {
		return err
	}
	c, err := CertifyIssuer(cross, newRoot, newKey.Public().(ed25519.PublicKey), groups, now)
	if err != nil {
		return err
	}
	if err := i.commit(Entry{Time: now, Act: ActRotated, Cert: cross.Raw, KeyLabel: label}); err != nil {
		return err
	}
	if err := i.commit(Entry{Time: now, Act: ActIssuer, Cert: c.Raw}); err != nil {
		return err
	}
	if err := i.useKey(newKey); err != nil {
		return err
	}
	return i.checkpoint(newRoot, now)
}
