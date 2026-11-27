// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// The organisation's relay mailboxes (spec/enrol/README.md).
// They carry nothing secret, and the relay can forge none of it: requests
// are bound to a token or signed by the current key, answers and CRLs are
// the issuer's signatures, the root is pinned or the recovery key's.
//
//   - EnrolMailbox: machines' requests (Request), which the issuer takes
//     and acknowledges.
//   - AnswersMailbox: the issuer's answers (Answer), each under its
//     request's id as replace key, kept a while; every machine reads them
//     and takes only its own.
//   - CRLMailbox: the issuer's newest CRL (CRLMessage), one replace key.
//   - RootMailbox: the organisation's current root and recovery
//     certificates (RootMessage), one replace key; after a rotation the
//     root is the recovery key's certificate of the new primary.
func EnrolMailbox(orgID string) string   { return "org." + orgID + ".enrol" }
func AnswersMailbox(orgID string) string { return "org." + orgID + ".answers" }
func RootMailbox(orgID string) string    { return "org." + orgID + ".root" }

// Request is one message of EnrolMailbox: an enrolment (ID: its token id)
// or a renewal (ID: random, the machine's own).
type Request struct {
	ID    string        `json:"id"`
	Enrol *EnrolRequest `json:"enrol,omitempty"`
	Renew *RenewRequest `json:"renew,omitempty"`
	// SignIn is an enrolment by a person's sign-in (ID: random, the device's own).
	SignIn *SignInRequest `json:"sign_in,omitempty"`
	// Order is the root's order (order.go), posted by the root's machine
	// (nfltr org approve; ID: random).
	Order *SignedOrder `json:"order,omitempty"`
	// IssuerRenewal is the root's answer to the issuer's renewal request
	// (SignIssuerRenewal), posted by the root's machine (nfltr org approve
	// of a renew wish; ID: random). The answer carries the issuer's
	// certificate it installed (Answer.Issuer).
	IssuerRenewal *IssuerRenewal `json:"issuer_renewal,omitempty"`
	// People is an act on the roster (people.go), the root's or an
	// admin's machine's (ID: random).
	People *PeopleRequest `json:"people,omitempty"`
	// Policy is the root's access policy (policy.go), posted by the
	// root's machine (nfltr access allow; ID: random).
	Policy *orgid.SignedPolicy `json:"policy,omitempty"`
	// Grant is an act on a grant (grant.go): a member machine's request,
	// an approver's answer, a revoke (ID: random).
	Grant *GrantRequest `json:"grant,omitempty"`
	// Audit is a machine's session audit lines, sealed to the issuer
	// (sessionaudit.go; ID: the batch's log and last seq, so a retry is
	// answered as the first post was).
	Audit *AuditRequest `json:"audit,omitempty"`
}

// Answer is the issuer's answer to request ID: the certificate and the
// issuer's (the chain a machine serves), or why it refused. An enrolment's
// answer may carry the machine key sealed to the certified key
// (SealMachineKey; OpenMachineKey on the machine). Every certificate comes
// with its SSH host certificate (HostCert; CheckHostCert on the machine).
type Answer struct {
	ID       string `json:"id"`
	Cert     []byte `json:"cert,omitempty"`
	Issuer   []byte `json:"issuer,omitempty"`
	HostCert []byte `json:"host_cert,omitempty"` // SSH wire form (Issuer.HostCert)
	// TokenMAC is an enrolment answer's MAC under its token (AnswerMAC):
	// the join takes no answer the relay made, under a root it holds the
	// keys of (spec/enrol/Join.tla InstallForged, mutant answer-unmacd;
	// lane SECFIX2, review S9).
	TokenMAC   []byte     `json:"token_mac,omitempty"`
	MachineKey *SealedKey `json:"machine_key,omitempty"`
	Refused    string     `json:"refused,omitempty"`
	// SignInEnded: the refusal is ErrSignInEnded (the device signs in again).
	SignInEnded bool `json:"sign_in_ended,omitempty"`
	// Revoked is the name an order revoked.
	Revoked string `json:"revoked,omitempty"`
	// Removal is what a people act's removal filed.
	Removal *Removal `json:"removal,omitempty"`
	// Policy is the number of the access policy the issuer holds after a
	// policy request (TakePolicy).
	Policy int64 `json:"policy,omitempty"`
	// Grant is what a grant act did (ApplyGrant).
	Grant *GrantAnswer `json:"grant,omitempty"`
	// Audit is where the issuer stands in the machine's audit log.
	Audit *AuditAnswer `json:"audit,omitempty"`
}

// RootMessage is the organisation's current root and its recovery, and
// the root's CRL of issuers once the owner revoked one (SignIssuerCRL;
// machines take it by a higher Number only, orgid.Verifier.TakeIssuerCRL).
type RootMessage struct {
	Root     []byte `json:"root"`
	Recovery []byte `json:"recovery"`
	Issuers  []byte `json:"issuers,omitempty"`
}

// NameOfMachine is the enrolled name, not revoked, whose certificates
// carry machine id id, "" if none (the account-revocation tie-in).
func (i *Issuer) NameOfMachine(id string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	for name, n := range i.names {
		if id != "" && n.machineID == id && !n.revoked {
			return name
		}
	}
	return ""
}

// LastCRL is the Number and NextUpdate of the issuer's last CRL (0: none
// yet): the issuer signs the next before NextUpdate (Enrol.tla Republish).
func (i *Issuer) LastCRL() (number int64, next time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.crlNumber, i.crlNext
}

// CRLDue: a revocation or a new issuer certificate (a renewal) came after
// the last CRL, so its successor is due now, not at CRLEvery old (one
// refused with ErrIssuerExpired, signed once the issuer is renewed).
func (i *Issuer) CRLDue() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.crlDue
}
