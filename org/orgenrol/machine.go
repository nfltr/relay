// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/internal/orgfiles"
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
	csr, err := csrOf(key)
	return key, csr, err
}

func csrOf(key ed25519.PrivateKey) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "nfltr org machine"}}, key)
}

// JoinKeyFile is the key a join made for its token, in the machine's
// directory until the join installs its answer: a join run again with the
// token (its answer was lost, or came after it gave up) asks with the same
// key, which the issuer answers again (spec/enrol/Join.tla Start, mutant
// new-key-per-join). The token's id is the PEM block's Token header.
const JoinKeyFile = "join.key"

// joinKey is the key kept in dir for tokenID and the id of the first
// request made for it (the PEM block's Request header), or a new key kept
// there with id, the first.
func joinKey(dir, tokenID, id string) (ed25519.PrivateKey, string, error) {
	f := filepath.Join(dir, JoinKeyFile)
	data, err := os.ReadFile(f) // #nosec G304 -- this machine's own directory
	if err != nil && !os.IsNotExist(err) {
		return nil, "", err
	}
	if b, _ := pem.Decode(data); b != nil && b.Headers["Token"] == tokenID {
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		key, ok := k.(ed25519.PrivateKey)
		if err != nil || !ok {
			return nil, "", fmt.Errorf("%s: not an Ed25519 key", f)
		}
		return key, b.Headers["Request"], nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil { // nosemgrep: incorrect-default-permission -- a directory needs x; 0o700 is owner-only
		return nil, "", err
	}
	return key, id, orgfiles.Write(f, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Token": tokenID, "Request": id}, Bytes: pk}), 0o600)
}

// Joined is an enrolment's outcome: the certificate, and the machine
// key when the issuer sealed one (KeyID "<machine id>.<generation>").
type Joined struct {
	Cert       *x509.Certificate
	KeyID      string
	MachineKey []byte
}

// Join enrols this machine into dir (orgmachine's layout) with token: the
// root and recovery from the relay, checked against pins (a root the
// pinned recovery key certifies too: a rotation since); the issuer's CRL;
// the token's key (JoinKeyFile: a new one the first time), its CSR bound
// to the token, the issuer's answer checked (for that key, under that
// root), and the machine key it seals opened (orgpki.OpenMachineKey). It
// waits up to wait in all; run again with the token, it asks again with
// the same key. The mailboxes are the token's organisation's
// (orgpki.TokenOrgID): after a rotation the root's fingerprint no longer
// derives their id.
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
	er, err := orgpki.NewEnrolRequest(token, nil) // its TokenID
	if err != nil {
		return Joined{}, err
	}
	// The request's id is this run's: the relay keeps a sender's
	// idempotency key a day, longer than the answer, so a run after an
	// earlier one's answer is gone must still reach the issuer. The first
	// run's answer, while the relay holds it, is taken too: it carries the
	// sealed A2A key, which an answer again may not (Join.tla Install).
	req := orgpki.Request{ID: randomID()}
	key, first, err := joinKey(dir, er.TokenID, req.ID)
	if err != nil {
		return Joined{}, err
	}
	csr, err := csrOf(key)
	if err != nil {
		return Joined{}, err
	}
	er, err = orgpki.NewEnrolRequest(token, csr)
	if err != nil {
		return Joined{}, err
	}
	req.Enrol = &er
	var a orgpki.Answer
	for {
		a, err = exchange(ctx, mb, orgID, req, min(AnswerWait, wait), first)
		if err == nil || ctx.Err() != nil || a.Refused != "" {
			break
		}
	}
	if a.Refused != "" {
		_ = os.Remove(filepath.Join(dir, JoinKeyFile)) // refused: the token answers this key no more
	}
	if err != nil {
		return Joined{}, err
	}
	if err := orgmachine.Checked(ver, a.Cert, a.Issuer, a.HostCert, key, "", now()); err != nil {
		return Joined{}, fmt.Errorf("the answer: %w", err)
	}
	if err := orgmachine.WriteFiles(dir, orgmachine.Enrolment{Root: rm.Root, Recovery: rm.Recovery, Cert: a.Cert, Issuer: a.Issuer, HostCert: a.HostCert, CRL: cm.CRL, Key: key}); err != nil {
		return Joined{}, err
	}
	_ = os.Remove(filepath.Join(dir, JoinKeyFile)) // installed: the machine's key now
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
	rootPin := pins.Root
	if orgid.Fingerprint(root) != pins.Root && orgid.Fingerprint(rec) == pins.Recovery {
		// A rotation since the pins were made: the pinned recovery key
		// certifies the new root, as a running machine takes a rotation
		// (orgid TakeRotation; spec/enrol/Join.tla Trusts, mutant
		// pin-root-only; enrol.pv RotClient).
		if err := rotatedRoot(root, rec, orgID); err != nil {
			return nil, nil, rm, cm, fmt.Errorf("the organisation's root is not the pinned one, nor certified by the pinned recovery key: %w", err)
		}
		rootPin = orgid.Fingerprint(root)
	}
	ver, err := orgid.NewVerifier(root, rec, rootPin, pins.Recovery)
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

// rotatedRoot checks a root the relay gives in place of the pinned one: a
// CA root of organisation orgID signed by the recovery key (orgid's
// rotation check, but for the order: a join holds no earlier root to be
// newer than).
func rotatedRoot(root, recovery *x509.Certificate, orgID string) error {
	if err := root.CheckSignatureFrom(recovery); err != nil {
		return fmt.Errorf("not signed by the recovery key: %w", err)
	}
	if id, err := orgid.OrgIDOfRoot(root); err != nil || id != orgID {
		return fmt.Errorf("not a root of %s", orgID)
	}
	if !root.IsCA || !root.BasicConstraintsValid {
		return errors.New("not a CA")
	}
	return nil
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

// Run keeps the machine until ctx ends; it returns once its follows did.
func (k Keeper) Run(ctx context.Context) {
	k = k.defaults()
	m, org := k.Machine, k.Machine.OrgID()
	var follows sync.WaitGroup
	defer follows.Wait() // nothing of Run writes the machine's directory once it returned (TestKeeperRunJoinsItsFollows)
	follows.Go(func() { followCRL(ctx, k.Mailbox, m, k.FollowEvery, k.Now, k.Logger) })
	follows.Go(func() {
		follow(ctx, k.Mailbox, orgpki.RootMailbox(org), k.FollowEvery, func(p []byte) error {
			var rm orgpki.RootMessage
			if err := json.Unmarshal(p, &rm); err != nil {
				return err
			}
			if _, err := m.TakeRotation(rm.Root); err != nil || rm.Issuers == nil {
				return err
			}
			_, err := m.TakeIssuerCRL(rm.Issuers)
			return err
		}, nil, k.Logger)
	})
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
	a, err := exchange(ctx, k.Mailbox, m.OrgID(), orgpki.Request{ID: randomID(), Renew: &rr}, k.AnswerWait)
	if err != nil {
		return err
	}
	return m.Install(a.Cert, a.Issuer, a.HostCert, key, k.Now())
}

// JoinSignIn enrols this device into dir by a person's sign-in
// (orgpki.Issuer.EnrolSignIn; spec/appenrol/AppEnrol.tla EnrolSSO): key is
// the device's organisation key and relayKey its relay key, the two the ID
// token's nonce names (appenrol.SignIn), rule the owner's sign-in rule.
// The organisation is orgID's, checked against pins as Join does; the
// answer is checked for key. Run again with the same key and a token for
// it, the issuer certifies the same name again (and moves its sign-in on:
// Reauth).
func JoinSignIn(ctx context.Context, mb Mailbox, dir string, pins Pins, orgID, rule, idToken string, key ed25519.PrivateKey, relayKey crypto.PublicKey, wait time.Duration, now func() time.Time) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	ver, _, rm, cm, err := trust(ctx, mb, orgID, pins, wait, now)
	if err != nil {
		return nil, err
	}
	csr, err := csrOf(key)
	if err != nil {
		return nil, err
	}
	sr, err := orgpki.NewSignInRequest(rule, idToken, csr, relayKey)
	if err != nil {
		return nil, err
	}
	a, err := exchange(ctx, mb, orgID, orgpki.Request{ID: randomID(), SignIn: &sr}, wait)
	if err != nil {
		return nil, err
	}
	if err := orgmachine.Checked(ver, a.Cert, a.Issuer, a.HostCert, key, "", now()); err != nil {
		return nil, fmt.Errorf("the answer: %w", err)
	}
	if err := orgmachine.WriteFiles(dir, orgmachine.Enrolment{Root: rm.Root, Recovery: rm.Recovery, Cert: a.Cert, Issuer: a.Issuer, HostCert: a.HostCert, CRL: cm.CRL, Key: key}); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(a.Cert)
}
