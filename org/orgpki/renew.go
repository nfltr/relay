// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

// Renewing an issuer that runs on another machine than its root (the root
// stays with its owner, spec/orgmove/README.md; spec/proverif/orgmove.pv
// queries 5-8, BIND:renew.*): the
// issuer signs a request (its key, groups and log head), the root's holder
// checks it against its own copy of the log (the issuer it pins) and
// answers with the issuer certificate and the root's checkpoint of that
// head, and the issuer installs the answer only when it names its own key
// and a head of its own log. CSR-style intermediate renewal: the root and
// the issuer key never share a machine.

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nfltr/relay/client/orgid"
)

// IssuerRenewalRequest is what `nfltr org issuer renew --request-out`
// writes on the issuer's machine.
type IssuerRenewalRequest struct {
	OrgID  string   `json:"org_id"`
	Key    []byte   `json:"issuer_key"` // Ed25519, the issuer's
	Groups []string `json:"groups"`
	Head   string   `json:"head"`          // the log head to checkpoint
	Sig    []byte   `json:"sig,omitempty"` // the issuer key's, over the rest
}

// IssuerRenewal is the root holder's answer (`nfltr org issuer sign`).
type IssuerRenewal struct {
	Cert    []byte `json:"cert"`     // the new issuer certificate
	Head    string `json:"head"`     // the request's head
	RootSig []byte `json:"root_sig"` // the root's checkpoint of Head
	// Issuers is the root's CRL of issuers re-signed with this renewal
	// (SignIssuerCRL with no revoke: its NextUpdate the new delegation's
	// end), when the root's machine holds one; the issuer's machine keeps
	// it if newer (orgissuer Store.TakeIssuers) and publishes it with the
	// root (spec/orgmove/OrgHosted.tla Renew, RootCRLCurrent).
	Issuers []byte `json:"issuers,omitempty"`
}

func renewalMessage(r IssuerRenewalRequest) []byte {
	r.Sig = nil
	b, _ := json.Marshal(r)
	return append([]byte("nfltr-org-issuer-renew-v1\x00"), b...)
}

// RenewalRequest is this issuer's request for groups at its current head,
// signed with its key. It commits nothing.
func (i *Issuer) RenewalRequest(groups []string) (IssuerRenewalRequest, error) {
	if err := validGroups(groups); err != nil {
		return IssuerRenewalRequest{}, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	r := IssuerRenewalRequest{OrgID: i.orgID, Key: i.key.Public().(ed25519.PublicKey), Groups: slices.Clone(groups), Head: i.head}
	r.Sig = ed25519.Sign(i.key, renewalMessage(r))
	return r, nil
}

// Pins is what a copy of the organisation's log pins without the issuer
// key: a moved organisation's tombstone on the root's machine is one.
type Pins struct {
	OrgID, RootLabel, RootKind string
	Root, Issuer               *x509.Certificate
}

// ReadPins verifies lines and reads the root and the current issuer.
func ReadPins(lines [][]byte) (Pins, error) {
	entries, _, err := VerifyLog(lines)
	if err != nil {
		return Pins{}, err
	}
	i := &Issuer{tokens: map[string]*tokenRec{}, names: map[string]*nameRec{}, certs: map[string]*certRec{}}
	for _, e := range entries {
		if err := i.apply(e); err != nil {
			return Pins{}, err
		}
	}
	if i.cert == nil {
		return Pins{}, errors.New("the log names no issuer under the current root")
	}
	return Pins{OrgID: i.orgID, RootLabel: i.rootLabel, RootKind: i.RootKind(), Root: i.root, Issuer: i.cert}, nil
}

// SignIssuerRenewal is the root holder's side: it answers req only when it
// is of the pinned organisation, names the pinned issuer's key and is
// signed by it (BIND:renew.pin, BIND:renew.reqsig), and asks for no group
// beyond the pinned issuer's unless widen (the owner named the groups).
// Two root signatures, as RenewIssuer: the certificate and the checkpoint.
func SignIssuerRenewal(p Pins, root crypto.Signer, req IssuerRenewalRequest, widen bool, now time.Time) (IssuerRenewal, error) {
	pub, ok := issuerKey(p.Issuer)
	switch {
	case !ok:
		return IssuerRenewal{}, errors.New("the pinned issuer holds no Ed25519 key")
	case req.OrgID != p.OrgID:
		return IssuerRenewal{}, fmt.Errorf("%w: the request is of organisation %q, not %s", ErrRefused, req.OrgID, p.OrgID)
	case !bytes.Equal(req.Key, pub):
		return IssuerRenewal{}, fmt.Errorf("%w: the request names another issuer key than the organisation's (%s)", ErrRefused, orgid.KeyFingerprint(pub))
	case !ed25519.Verify(pub, renewalMessage(req), req.Sig):
		return IssuerRenewal{}, fmt.Errorf("%w: the request is not signed by the organisation's issuer", ErrRefused)
	case len(req.Head) != 64:
		return IssuerRenewal{}, fmt.Errorf("%w: the request names no log head", ErrRefused)
	}
	for _, g := range req.Groups {
		if !widen && !slices.Contains(p.Issuer.Subject.OrganizationalUnit, g) {
			return IssuerRenewal{}, fmt.Errorf("%w: the request widens the issuer's groups (%v, now %v): name them with --groups to sign", ErrRefused, req.Groups, p.Issuer.Subject.OrganizationalUnit)
		}
	}
	c, err := CertifyIssuer(p.Root, root, pub, req.Groups, now)
	if err != nil {
		return IssuerRenewal{}, err
	}
	sig, err := signCheckpoint(root, p.OrgID, req.Head)
	if err != nil {
		return IssuerRenewal{}, fmt.Errorf("root signature: %w", err)
	}
	return IssuerRenewal{Cert: c.Raw, Head: req.Head, RootSig: sig}, nil
}

// InstallRenewal takes the root holder's answer: its certificate chains
// to this log's root (BIND:renew.root), names this issuer's key
// (BIND:renew.key) and ends after the current one (an old answer is not
// taken again), and its root signature checkpoints a head of this log
// (BIND:renew.head). It commits the issuer line, then the checkpoint of
// that head with the issuer's signature too.
func (i *Issuer) InstallRenewal(a IssuerRenewal, now time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	c, err := x509.ParseCertificate(a.Cert)
	if err != nil {
		return fmt.Errorf("the answer's certificate: %w", err)
	}
	if err := c.CheckSignatureFrom(i.root); err != nil {
		return fmt.Errorf("%w: the answer's certificate is not the organisation root's: %v", ErrRefused, err)
	}
	if pub, ok := issuerKey(c); !ok || !pub.Equal(i.key.Public()) {
		return fmt.Errorf("%w: the answer certifies another key than this issuer's", ErrRefused)
	}
	if !c.NotAfter.After(i.cert.NotAfter) {
		return fmt.Errorf("%w: the answer's certificate ends %s, not after the current one: an old answer", ErrRefused, c.NotAfter.UTC().Format(time.RFC3339))
	}
	if !i.heads[a.Head] {
		return fmt.Errorf("%w: the answer checkpoints %q, not a head of this log", ErrRefused, a.Head)
	}
	msg := checkpointMessage(i.orgID, a.Head)
	if !verifyRootSig(i.root, msg, a.RootSig) {
		return fmt.Errorf("%w: the answer's checkpoint is not the root's signature of that head", ErrRefused)
	}
	if err := i.commit(Entry{Time: now, Act: ActIssuer, Cert: c.Raw}); err != nil {
		return err
	}
	return i.commit(Entry{Time: now, Act: ActCheckpoint, Head: a.Head, RootSig: a.RootSig, IssuerSig: ed25519.Sign(i.key, msg)})
}
