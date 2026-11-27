// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// Acts in the audit log.
const (
	ActInit        = "init"          // Cert: the root; Recovery: the recovery's certificate; KeyLabel: the root primary's
	ActIssuer      = "issuer"        // Cert: an issuer certificate the root signed
	ActRotated     = "rotated"       // Cert: the new root, cross-signed by the recovery key; KeyLabel
	ActToken       = "token"         // Token, Name, Groups, MachineID, Person, App, NotAfter (the token's expiry)
	ActIssued      = "issued"        // Name, Groups, MachineID, Person, App, Serial, Key, Digest, NotAfter, Token; by sign-in IdP, Subject, ClientID, AuthUntil
	ActRenewed     = "renewed"       // as issued; From: the serial it renews
	ActRebound     = "rebound"       // as issued, by a rebind token: MachineID the name's new one; every earlier serial of Name retired
	ActRefused     = "refused"       // Reason; Token or Serial when known
	ActRevoked     = "revoked"       // Name; or Person or App: every name of it, and no enrolment of it from now; a person's removal: Actor, ActorRole, Role (the person's), Filed
	ActInvite      = "invite"        // Person, Role, Invite (its key), NotAfter, Actor, ActorRole (people.go); a join is the issued line naming Invite and Role
	ActRole        = "role"          // Person, Role: the new one, Actor, ActorRole (people.go)
	ActCRL         = "crl"           // Number, NotAfter (its NextUpdate)
	ActCheckpoint  = "checkpoint"    // Head; IssuerSig; RootSig (at an issuer renewal)
	ActMoved       = "moved"         // Key: the new machine's receive key fingerprint (the fence, move.go)
	ActArrived     = "arrived"       // Key: the receive key the fence named, on the new machine
	ActRule        = "rule"          // Rule: a sign-in rule added or replaced (signin.go)
	ActRuleRemoved = "rule-removed"  // Name: the sign-in rule's id
	ActRestored    = "restored"      // Number, NotAfter, Serials: the published CRL a restore from a backup took (restore.go)
	ActAdopted     = "adopted"       // as issued: a certificate the lost issuer issued after the backup, adopted at its renewal (restore.go)
	ActPolicy      = "policy"        // Policy, RootSig, Number: the root's access policy taken (policy.go)
	ActGrantAsk    = "grant-request" // Grant (ID, Who, Where, Service, ForS, Reason, Digest), Name, Actor: the requester; Cert: its certificate; NotAfter: void after (grant.go)
	ActGrant       = "grant"         // Grant (ID, Who, Where, Service, ForS, Serial, Until), Actor: the approver; Cert: the grant certificate
	ActGrantDeny   = "grant-deny"    // Grant.ID, Actor (ActorRole owner: the root): the request's final answer
	ActGrantRevoke = "grant-revoke"  // Grant.Serial, Grant.ID, Actor (ActorRole owner: the root)
)

// Entry is one line of the issuer's hash-chained JSON-lines log. Prev is
// the SHA-256 of the previous line's bytes ("" for the first).
type Entry struct {
	Time      time.Time   `json:"time"`
	Act       string      `json:"act"`
	Name      string      `json:"name,omitempty"`
	Groups    []string    `json:"groups,omitempty"`
	MachineID string      `json:"machine_id,omitempty"`
	Person    string      `json:"person,omitempty"`
	App       string      `json:"app,omitempty"`
	Serial    string      `json:"serial,omitempty"`
	Serials   []string    `json:"serials,omitempty"` // a restored line's: the published CRL's
	From      string      `json:"from,omitempty"`
	Key       string      `json:"key,omitempty"`
	Digest    string      `json:"digest,omitempty"`
	Token     string      `json:"token,omitempty"`
	Rebind    bool        `json:"rebind,omitempty"` // a token: a rebind token (MakeRebindToken)
	NotAfter  time.Time   `json:"not_after,omitzero"`
	Number    int64       `json:"number,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	KeyLabel  string      `json:"key_label,omitempty"`
	RootKind  string      `json:"root_kind,omitempty"`
	Cert      []byte      `json:"cert,omitempty"`
	Recovery  []byte      `json:"recovery,omitempty"`
	Head      string      `json:"head,omitempty"`
	IssuerSig []byte      `json:"issuer_sig,omitempty"`
	RootSig   []byte      `json:"root_sig,omitempty"`
	Rule      *SignInRule `json:"rule,omitempty"`
	IdP       string      `json:"idp,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	ClientID  string      `json:"client_id,omitempty"`
	AuthUntil time.Time   `json:"auth_until,omitzero"`
	Role      string      `json:"role,omitempty"`       // people.go: a person's role
	Invite    string      `json:"invite,omitempty"`     // people.go: an invite's id
	Actor     string      `json:"actor,omitempty"`      // people.go: the admin who acted ("" with ActorRole owner: the root)
	ActorRole string      `json:"actor_role,omitempty"` // people.go
	Filed     []Filed     `json:"filed,omitempty"`      // people.go: a removal's machines
	Policy    []byte      `json:"policy,omitempty"`     // policy.go: the root's signed policy body (its signature: RootSig)
	Grant     *GrantEntry `json:"grant,omitempty"`      // grant.go
	Prev      string      `json:"prev"`
}

func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// checkpointMessage is what a checkpoint signs. It is not DER (an x509
// TBS starts with 0x30), so a root signature over one is never a
// certificate.
func checkpointMessage(orgID, head string) []byte {
	return []byte("nfltr-org-checkpoint-v1\x00" + orgID + "\x00" + head)
}

// signCheckpoint signs a checkpoint message with the root primary.
func signCheckpoint(root crypto.Signer, orgID, head string) ([]byte, error) {
	return crypto.SignMessage(root, rand.Reader, checkpointMessage(orgID, head), crypto.SHA256)
}

func verifyRootSig(root *x509.Certificate, msg, sig []byte) bool {
	return orgid.RootSigned(root, msg, sig)
}

// encode makes e's line, chained to head.
func encode(e Entry, head string) ([]byte, error) {
	e.Prev = head
	return json.Marshal(e)
}

// VerifyLog checks a whole log: every line chains to the one before, the
// first is an init, each issuer certificate chains to the root of its
// time, each rotation is the recovery key's, and every checkpoint's
// signatures are the issuer's and the root's of its time. Lines lost at
// the tail are not seen here: Issuer.CheckPublishedHead holds the log to
// the head the issuer last published.
// It returns the entries and the head.
func VerifyLog(lines [][]byte) ([]Entry, string, error) {
	var (
		entries  []Entry
		head     string
		root     *x509.Certificate
		recovery *x509.Certificate
		issuer   *x509.Certificate
		orgID    string
		fence    string // the receive key of a fence not yet followed by its arrival
		seen     = map[string]bool{}
	)
	for i, line := range lines {
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, "", fmt.Errorf("audit line %d: %w", i+1, err)
		}
		if e.Prev != head {
			return nil, "", fmt.Errorf("audit line %d: chain broken (prev %q, want %q)", i+1, e.Prev, head)
		}
		if (i == 0) != (e.Act == ActInit) {
			return nil, "", fmt.Errorf("audit line %d: %s; the log starts with its one init", i+1, e.Act)
		}
		// After a fence only its arrival (OrgMove.tla OldCannotIssue).
		if (fence != "" || e.Act == ActArrived) && (e.Act != ActArrived || fence == "" || e.Key != fence) {
			return nil, "", fmt.Errorf("audit line %d: %s after the fence to %q; only its arrival follows a fence", i+1, e.Act, fence)
		}
		if e.Act == ActMoved && e.Key == "" {
			return nil, "", fmt.Errorf("audit line %d: a fence names no receive key", i+1)
		}
		fence = ""
		switch e.Act {
		case ActMoved:
			fence = e.Key
		case ActInit:
			var err error
			if root, err = x509.ParseCertificate(e.Cert); err == nil {
				recovery, err = x509.ParseCertificate(e.Recovery)
			}
			if err == nil {
				orgID, err = orgid.OrgIDOfRoot(root)
			}
			if err == nil {
				err = root.CheckSignatureFrom(root)
			}
			if err != nil {
				return nil, "", fmt.Errorf("audit line %d: init: %w", i+1, err)
			}
		case ActRotated:
			c, err := x509.ParseCertificate(e.Cert)
			if err == nil {
				err = checkRotation(c, recovery, root)
			}
			if err != nil {
				return nil, "", fmt.Errorf("audit line %d: rotation: %w", i+1, err)
			}
			root, issuer = c, nil
		case ActIssuer:
			c, err := x509.ParseCertificate(e.Cert)
			if err == nil {
				err = c.CheckSignatureFrom(root)
			}
			if err != nil {
				return nil, "", fmt.Errorf("audit line %d: issuer: %w", i+1, err)
			}
			issuer = c
		case ActCheckpoint:
			// The head now, or an earlier one: a remote renewal's (renew.go)
			// root checkpoints the head its request named.
			if e.Head != head && !seen[e.Head] {
				return nil, "", fmt.Errorf("audit line %d: checkpoint of %q, not a head of this log", i+1, e.Head)
			}
			msg := checkpointMessage(orgID, e.Head)
			if pub, ok := issuerKey(issuer); !ok || !ed25519.Verify(pub, msg, e.IssuerSig) {
				return nil, "", fmt.Errorf("audit line %d: checkpoint: not the issuer's signature", i+1)
			}
			// Every checkpoint is the root's too (RenewIssuer, InstallRenewal
			// sign none without it): one without is refused, not skipped
			// (lane SECFIX2, review S19; mutant checkpoint-root-optional).
			if !verifyRootSig(root, msg, e.RootSig) {
				return nil, "", fmt.Errorf("audit line %d: checkpoint: not the root's signature", i+1)
			}
		}
		entries = append(entries, e)
		head = lineHash(line)
		seen[head] = true
	}
	if len(entries) == 0 {
		return nil, "", errors.New("audit log is empty")
	}
	return entries, head, nil
}

func issuerKey(c *x509.Certificate) (ed25519.PublicKey, bool) {
	if c == nil {
		return nil, false
	}
	pub, ok := c.PublicKey.(ed25519.PublicKey)
	return pub, ok
}
