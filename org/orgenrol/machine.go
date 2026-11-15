// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgpki"
)

// Pins are a machine's first-use values: the organisation root's and its
// recovery's fingerprints, provisioned with the token.
type Pins struct {
	Root, Recovery string
}

func newKeyCSR() (ed25519.PrivateKey, []byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "nfltr org machine"}}, key)
	return key, csr, err
}

// Joined is an enrolment's outcome: the certificate, and the machine
// key when the issuer sealed one (KeyID "<machine id>.<generation>").
type Joined struct {
	Cert       *x509.Certificate
	KeyID      string
	MachineKey []byte
}

// Join enrols this machine into dir (orgmachine's layout) with token: the
// root and recovery from the relay, checked against pins; the issuer's
// CRL; a new key, its CSR bound to the token, the issuer's answer checked
// (for that key, under the pinned root), and the machine key it seals opened
// (orgpki.OpenMachineKey). It waits up to wait in all. The mailboxes are
// the token's organisation's (orgpki.TokenOrgID): after a rotation the
// root's fingerprint no longer derives their id.
func Join(ctx context.Context, mb Mailbox, dir string, pins Pins, token string, wait time.Duration, now func() time.Time) (Joined, error) {
	orgID, err := orgpki.TokenOrgID(token)
	if err != nil {
		return Joined{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	ver, root, rm, cm, err := trust(ctx, mb, orgID, pins, wait, now)
	if err != nil {
		return Joined{}, err
	}
	key, csr, err := newKeyCSR()
	if err != nil {
		return Joined{}, err
	}
	er, err := orgpki.NewEnrolRequest(token, csr)
	if err != nil {
		return Joined{}, err
	}
	// One request (one key) for the token: it is redeemed once, so asking
	// again re-reads the answer to the same request.
	// replayed: the first post found the token's request posted already,
	// by another machine or an earlier join (its answer is for that key).
	var a orgpki.Answer
	replayed, first := false, true
	for {
		var posted bool
		a, posted, err = exchange(ctx, mb, orgID, orgpki.Request{ID: er.TokenID, Enrol: &er}, min(AnswerWait, wait))
		replayed, first = replayed || (first && posted), false
		if err == nil || ctx.Err() != nil || a.Refused != "" {
			break
		}
	}
	if err != nil {
		return Joined{}, err
	}
	if err := orgmachine.Checked(ver, a.Cert, a.Issuer, a.HostCert, key, "", now()); err != nil {
		// The answer under the token's id is for another key: another
		// request redeemed the token. A replay from another relay machine
		// is not reported as a duplicate (idempotency is per machine).
		if replayed || errors.Is(err, orgmachine.ErrNotForKey) {
			return Joined{}, fmt.Errorf("the token was redeemed already: a request for it was posted before this join (another machine, or an earlier join of this one), and a token enrols one machine once; ask the organisation's owner for a new token (nfltr org token) (%w)", err)
		}
		return Joined{}, fmt.Errorf("the answer: %w", err)
	}
	if err := orgmachine.WriteFiles(dir, orgmachine.Enrolment{Root: rm.Root, Recovery: rm.Recovery, Cert: a.Cert, Issuer: a.Issuer, HostCert: a.HostCert, CRL: cm.CRL, Key: key}); err != nil {
		return Joined{}, err
	}
	var j Joined
	if j.Cert, err = x509.ParseCertificate(a.Cert); err != nil || a.MachineKey == nil {
		return j, err
	}
	// Enrolled either way (the token is spent); a key that does not open
	// is refused, never used.
	if j.MachineKey, err = orgpki.OpenMachineKey(*a.MachineKey, er.TokenID, a.Cert, a.Issuer, root, key, now()); err != nil {
		return Joined{Cert: j.Cert}, fmt.Errorf("enrolled, but the answer's A2A key is refused: %w", err)
	}
	j.KeyID = a.MachineKey.KeyID
	return j, nil
}

// Trust is the organisation orgID as pins name it: its root and recovery
// from the relay, checked against pins, and its issuer's current CRL
// taken; wait bounds each read. The root holder checks a machine it keys
// under it (a machine-key holder checking a machine).
func Trust(ctx context.Context, mb Mailbox, orgID string, pins Pins, wait time.Duration, now func() time.Time) (*orgid.Verifier, error) {
	ver, _, _, _, err := trust(ctx, mb, orgID, pins, wait, now)
	return ver, err
}

// trust is Trust with what Join keeps of it: the root and the messages.
func trust(ctx context.Context, mb Mailbox, orgID string, pins Pins, wait time.Duration, now func() time.Time) (*orgid.Verifier, *x509.Certificate, orgpki.RootMessage, orgid.CRLMessage, error) {
	var rm orgpki.RootMessage
	var cm orgid.CRLMessage
	data, err := latest(ctx, mb, orgpki.RootMailbox(orgID), min(pollWait, wait))
	if err == nil && data == nil {
		err = errNoMessage
	}
	if err != nil {
		return nil, nil, rm, cm, fmt.Errorf("the organisation's root: %w (is the issuer running: nfltr node or nfltr org serve on the issuer's machine?)", err)
	}
	if err := json.Unmarshal(data, &rm); err != nil {
		return nil, nil, rm, cm, err
	}
	root, err := x509.ParseCertificate(rm.Root)
	if err != nil {
		return nil, nil, rm, cm, err
	}
	rec, err := x509.ParseCertificate(rm.Recovery)
	if err != nil {
		return nil, nil, rm, cm, err
	}
	ver, err := orgid.NewVerifier(root, rec, pins.Root, pins.Recovery)
	if err != nil {
		return nil, nil, rm, cm, err
	}
	if data, err = latest(ctx, mb, orgid.CRLMailbox(orgID), min(pollWait, wait)); err == nil && data == nil {
		err = errNoMessage
	}
	if err != nil {
		return nil, nil, rm, cm, fmt.Errorf("the issuer's CRL: %w", err)
	}
	if err := json.Unmarshal(data, &cm); err != nil {
		return nil, nil, rm, cm, err
	}
	iss, err := x509.ParseCertificate(cm.Issuer)
	if err != nil {
		return nil, nil, rm, cm, err
	}
	if err := ver.TakeCRL(cm.CRL, iss, now()); err != nil {
		return nil, nil, rm, cm, fmt.Errorf("the issuer's CRL: %w", err)
	}
	return ver, root, rm, cm, nil
}

// followCRL takes the organisation's CRL pushes into m (its Changed cuts
// the sessions a CRL refuses) until ctx ends, a fresh read every every.
// A client process without a Keeper follows with relay client
// orgid.Follow.
func followCRL(ctx context.Context, mb Mailbox, m *orgmachine.Machine, every time.Duration, now func() time.Time, logger *slog.Logger) {
	follow(ctx, mb, orgid.CRLMailbox(m.OrgID()), every, func(p []byte) error {
		var cm orgid.CRLMessage
		if err := json.Unmarshal(p, &cm); err != nil {
			return err
		}
		_, err := m.TakeCRL(cm.CRL, cm.Issuer, now())
		return err
	}, m.Changed, logger)
}

// Keeper keeps a machine current: it follows the CRL and the root
// (FollowEvery: the backstop) and renews when RenewDue says (at 2/3 of the
// certificate's lifetime, at once after a rotation), asking again with a
// new key when no answer came (Enrol.tla Request, mutant no-retry).
type Keeper struct {
	Mailbox Mailbox
	Machine *orgmachine.Machine
	Logger  *slog.Logger
	// Now, AnswerWait, RetryWait, FollowEvery: zero is time.Now and the
	// package's defaults (tests shorten them).
	Now                                func() time.Time
	AnswerWait, RetryWait, FollowEvery time.Duration
}

func (k Keeper) defaults() Keeper {
	if k.Now == nil {
		k.Now = time.Now
	}
	if k.AnswerWait <= 0 {
		k.AnswerWait = AnswerWait
	}
	if k.RetryWait <= 0 {
		k.RetryWait = retryWait
	}
	if k.FollowEvery <= 0 {
		k.FollowEvery = FollowEvery
	}
	return k
}

// Run keeps the machine until ctx ends.
func (k Keeper) Run(ctx context.Context) {
	k = k.defaults()
	m, org := k.Machine, k.Machine.OrgID()
	go followCRL(ctx, k.Mailbox, m, k.FollowEvery, k.Now, k.Logger)
	go follow(ctx, k.Mailbox, orgpki.RootMailbox(org), k.FollowEvery, func(p []byte) error {
		var rm orgpki.RootMessage
		if err := json.Unmarshal(p, &rm); err != nil {
			return err
		}
		_, err := m.TakeRotation(rm.Root)
		return err
	}, nil, k.Logger)
	for ctx.Err() == nil {
		changed := m.Changed()
		if d := m.RenewDue(k.Now()).Sub(k.Now()); d > 0 {
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
			case <-changed: // a rotation, or another process renewed
			case <-t.C:
			}
			t.Stop()
			continue
		}
		switch err := k.renew(ctx); {
		case err == nil || ctx.Err() != nil:
		case errors.Is(err, ErrExpired):
			k.Logger.Error("org: this machine's certificate expired; enrol it again (nfltr org join with a new token)")
			sleepCtx(ctx, k.FollowEvery)
		default:
			k.Logger.Warn("org: renewal failed (asking again with a new key)", "error", err)
			sleepCtx(ctx, k.RetryWait)
		}
	}
}

// ErrExpired: the machine's certificate expired; the issuer renews no
// expired certificate (Enrol.tla Issue), so only a new token's enrolment
// brings it back.
var ErrExpired = errors.New("the certificate expired: enrol again with a new token (nfltr org join)")

// renew asks the issuer once for a certificate of a new key, signed by the
// current one, under the machine's renewal lock.
func (k Keeper) renew(ctx context.Context) error {
	m := k.Machine
	unlock, err := m.LockRenewal()
	if err != nil {
		return err
	}
	defer unlock()
	now := k.Now()
	if _, err := m.Reload(now); err != nil {
		return err
	}
	if m.RenewDue(now).After(now) {
		return nil // another process renewed
	}
	cur, curKey := m.Current()
	if !now.Before(cur.NotAfter) {
		return ErrExpired
	}
	key, csr, err := newKeyCSR()
	if err != nil {
		return err
	}
	rr := orgpki.NewRenewRequest(cur.Raw, curKey, csr)
	a, _, err := exchange(ctx, k.Mailbox, m.OrgID(), orgpki.Request{ID: randomID(), Renew: &rr}, k.AnswerWait)
	if err != nil {
		return err
	}
	return m.Install(a.Cert, a.Issuer, a.HostCert, key, k.Now())
}
