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
	"encoding/hex"
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
// recovery's fingerprints, provisioned with the token, and MachineID, its
// relay machine id (none: ""), which Join states under the token's MAC
// for the issuer to bind where the token names none (spec/enrol/Join.tla
// JoinedBound: no move at the first serve).
type Pins struct {
	Root, Recovery string
	MachineID      string
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

// RenewKeyFile keeps a renewal's key until its answer is installed: asked
// again (a timeout, or another process), the renewal is for the same key,
// so an answer the machine never took (late, lost, or its process ended
// first) is answered again rather than superseding the certificate it
// holds (Enrol.tla Request, mutant new-key-per-retry; lane CANARYCERT).
const RenewKeyFile = "renew.key"

// joinKey is the key kept in dir for tokenID and the id of the first
// request made for it (the PEM block's Request header), or a new key kept
// there with id, the first.
func joinKey(dir, tokenID, id string) (ed25519.PrivateKey, string, error) {
	return pendingKey(dir, JoinKeyFile, "Token", tokenID, id)
}

// renewKey is joinKey of a renewal of serial (hex) in dir: the key kept
// for it, or a new one.
func renewKey(dir, serial, id string) (ed25519.PrivateKey, string, error) {
	return pendingKey(dir, RenewKeyFile, "From", serial, id)
}

// pendingKey is the key file name in dir keeps for header's value and the
// id of the first request made for it (the Request header), or a new key
// kept there with id, the first.
func pendingKey(dir, name, header, value, id string) (ed25519.PrivateKey, string, error) {
	f := filepath.Join(dir, name)
	data, err := os.ReadFile(f) // #nosec G304 -- this machine's own directory
	if err != nil && !os.IsNotExist(err) {
		return nil, "", err
	}
	if b, _ := pem.Decode(data); b != nil && b.Headers[header] == value {
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
	return key, id, orgfiles.Write(f, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{header: value, "Request": id}, Bytes: pk}), 0o600)
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
	nb, err := orgpki.TokenRootNotBefore(token)
	if err != nil {
		return Joined{}, err
	}
	ver, root, rm, cm, err := trust(ctx, mb, orgID, pins, nb, wait, now)
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
	er, err = orgpki.NewEnrolRequestFor(token, csr, pins.MachineID)
	if err != nil {
		return Joined{}, err
	}
	req.Enrol = &er
	traceJoinStart(orgID, dir, er.TokenID, key.Public(), req.ID, first)
	var a orgpki.Answer
	for {
		a, err = exchange(ctx, mb, orgID, req, min(AnswerWait, wait), first)
		if err == nil || ctx.Err() != nil || a.Refused != "" {
			break
		}
	}
	if a.Refused != "" {
		_ = os.Remove(filepath.Join(dir, JoinKeyFile)) // refused: the token answers this key no more
		traceJoinEnd(orgID, dir, er.TokenID, "refused", a)
	}
	if err != nil {
		if a.Refused == "" {
			traceJoinEnd(orgID, dir, er.TokenID, "failed", a)
		}
		return Joined{}, err
	}
	if err := orgpki.CheckAnswerMAC(token, a.Cert, a.Issuer, a.TokenMAC); err != nil { // Join.tla JoinedByIssuer
		traceJoinEnd(orgID, dir, er.TokenID, "failed", a)
		return Joined{}, fmt.Errorf("the answer: %w", err)
	}
	if err := orgmachine.Checked(ver, a.Cert, a.Issuer, a.HostCert, key, "", now()); err != nil {
		traceJoinEnd(orgID, dir, er.TokenID, "failed", a)
		return Joined{}, fmt.Errorf("the answer: %w", err)
	}
	if err := orgmachine.WriteFiles(dir, orgmachine.Enrolment{Root: rm.Root, Recovery: rm.Recovery, Cert: a.Cert, Issuer: a.Issuer, HostCert: a.HostCert, CRL: cm.CRL, Issuers: rm.Issuers, Key: key}); err != nil {
		traceJoinEnd(orgID, dir, er.TokenID, "failed", a)
		return Joined{}, err
	}
	_ = os.Remove(filepath.Join(dir, JoinKeyFile)) // installed: the machine's key now
	traceJoinEnd(orgID, dir, er.TokenID, "joined", a)
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
	ver, _, _, _, err := trust(ctx, mb, orgID, pins, time.Time{}, wait, now)
	return ver, err
}

// trust is Trust with what Join keeps of it: the root and the messages.
// A root older than notBefore (the token's root's: zero for none) is
// refused, the pinned one too (Join.tla JoinRootNotOlder).
func trust(ctx context.Context, mb Mailbox, orgID string, pins Pins, notBefore time.Time, wait time.Duration, now func() time.Time) (*orgid.Verifier, *x509.Certificate, orgpki.RootMessage, orgid.CRLMessage, error) {
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
	if root.NotBefore.Before(notBefore) {
		traceJoinRoot(orgID, pins, root, rec, notBefore, false)
		return nil, nil, rm, cm, fmt.Errorf("the organisation's root (of %s) is older than the root the token was made under (of %s): a superseded root", root.NotBefore.UTC().Format(time.RFC3339), notBefore.UTC().Format(time.RFC3339))
	}
	rootPin := pins.Root
	if orgid.Fingerprint(root) != pins.Root && orgid.Fingerprint(rec) == pins.Recovery {
		// A rotation since the pins were made: the pinned recovery key
		// certifies the new root, as a running machine takes a rotation
		// (orgid TakeRotation; spec/enrol/Join.tla Trusts, mutant
		// pin-root-only; enrol.pv RotClient).
		if err := rotatedRoot(root, rec, orgID); err != nil {
			traceJoinRoot(orgID, pins, root, rec, notBefore, false)
			return nil, nil, rm, cm, fmt.Errorf("the organisation's root is not the pinned one, nor certified by the pinned recovery key: %w", err)
		}
		rootPin = orgid.Fingerprint(root)
	}
	ver, err := orgid.NewVerifier(root, rec, rootPin, pins.Recovery)
	traceJoinRoot(orgID, pins, root, rec, notBefore, err == nil)
	if err != nil {
		return nil, nil, rm, cm, err
	}
	// The root's CRL of issuers beside it, taken before anything is
	// checked: a joining machine refuses a revoked issuer (its answer
	// too) from its first session (OrgHosted.tla Deliver).
	if rm.Issuers != nil {
		if err := ver.TakeIssuerCRL(rm.Issuers); err != nil {
			return nil, nil, rm, cm, fmt.Errorf("the organisation's root: %w", err)
		}
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
// the sessions a CRL refuses) until ctx ends, a fresh read every every,
// and the relay's copy of it when mb keeps one (CRLCopy: a mailbox outage
// no longer lapses the CRL, CrlCarriers.tla), and the relay's copy of the
// status for the access rules when mb keeps that (orgid.StatusCopy). A client process without a
// Keeper follows with relay client orgid.Follow, which does the same.
func followCRL(ctx context.Context, mb Mailbox, m *orgmachine.Machine, every time.Duration, now func() time.Time, logger *slog.Logger) {
	// apply(via): the take of one carrier's message (traced with its
	// carrier: CrlCarriers.tla Push, ReadCopy).
	apply := func(via string) func([]byte) error {
		return func(p []byte) error {
			var cm orgid.CRLMessage
			if err := json.Unmarshal(p, &cm); err != nil {
				return err
			}
			t := now()
			took, err := m.TakeCRL(cm.CRL, cm.Issuer, t)
			traceCarry(via, m, cm.CRL, t, took, err)
			return err
		}
	}
	var wg sync.WaitGroup
	if cp, ok := mb.(CRLCopy); ok {
		wg.Go(func() { readCopy(ctx, "CRL", cp.OrgCRL, m.OrgID(), every, apply("copy"), m.Changed, logger) })
	}
	// The access rules ride in the issuer's status (relay-server
	// spec/GroupMirror.tla PeerTake); the CRL push the issuer sends when
	// it takes a policy wakes this read (m.Changed).
	if sc, ok := mb.(orgid.StatusCopy); ok {
		take := func(p []byte) error { _, err := m.TakeStatus(p, now()); return err }
		wg.Go(func() { readCopy(ctx, "status", sc.OrgStatus, m.OrgID(), every, take, m.Changed, logger) })
	}
	wg.Go(func() { orgid.WarnStale(ctx, every, func() error { return m.CRLStale(now()) }, logger) })
	follow(ctx, mb, orgid.CRLMailbox(m.OrgID()), every, apply("mailbox"), m.Changed, logger)
	wg.Wait()
}

// Keeper keeps a machine current: it follows the CRL and the root
// (FollowEvery: the backstop) and renews when RenewDue says (at half the
// certificate's lifetime, at once after a rotation), asking again for the
// same key when no answer came (RenewKeyFile; Enrol.tla Request, mutants no-retry, new-key-per-retry), also
// past the certificate's NotAfter until orgpki.RenewGrace after it (an
// issuer out of reach through the renewal window: RenewsAfterExpiry).
// Failed attempts back off from RetryWait, doubling to FollowEvery, and a
// change of the machine (a CRL taken: the issuer's mailbox is back) asks
// again at once. When the machine's relay machine id is no longer its
// certificate's (it enrolled with the relay again: nfltr config login),
// the keeper asks at once to move its name there (Enrol.tla Move), and
// keeps renewing under the old id when the issuer refuses.
type Keeper struct {
	Mailbox Mailbox
	Machine *orgmachine.Machine
	Logger  *slog.Logger
	// RelayMachineID is the machine's relay machine id now (its account
	// certificate's), "" unknown; nil: no move.
	RelayMachineID func() string
	// MachineKey takes the A2A machine key a move's answer seals (an
	// issuer with an A2A root: the new id's key, its id <machine id>.<gen>),
	// opened only as this machine's own request's (nfltr
	// spec/proverif/a2a_keytransfer.pv Move, mv.key); nil: not taken. Its
	// error is logged: the machine moved, without its key.
	MachineKey func(keyID string, key []byte) error
	// Now, AnswerWait, RetryWait, FollowEvery: zero is time.Now and the
	// package's defaults (tests shorten them).
	Now                                func() time.Time
	AnswerWait, RetryWait, FollowEvery time.Duration
	// WakeEvery bounds the wait for the renewal: the keeper reads the
	// clock again at least this often (zero: a minute).
	WakeEvery time.Duration
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
	if k.WakeEvery <= 0 {
		k.WakeEvery = wakeEvery
	}
	return k
}

// wakeEvery bounds one timer of the wait for the renewal: timers run on
// the monotonic clock, which stands still while the host sleeps, and the
// certificate's lifetime is wall clock (guard
// TestKeeperRenewsOnTimeAfterTheHostSlept).
const wakeEvery = time.Minute

// Run keeps the machine until ctx ends; it returns once its follows did.
func (k Keeper) Run(ctx context.Context) {
	k = k.defaults()
	m, org := k.Machine, k.Machine.OrgID()
	var follows sync.WaitGroup
	defer follows.Wait() // nothing of Run writes the machine's directory once it returned (TestKeeperRunJoinsItsFollows)
	follows.Go(func() { followCRL(ctx, k.Mailbox, m, k.FollowEvery, k.Now, k.Logger) })
	follows.Go(func() { shipAudit(ctx, k.Mailbox, m, k.AnswerWait, k.Now, k.Logger) }) // auditship.go
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
	retry := k.RetryWait
	refusedMove := "" // a move the issuer refused: renewals keep the old id
	for ctx.Err() == nil {
		changed := m.Changed()
		move := k.moveTo(refusedMove)
		if d := m.RenewDue(k.Now()).Sub(k.Now()); d > 0 && move == "" {
			t := time.NewTimer(min(d, k.WakeEvery))
			select {
			case <-ctx.Done():
			case <-changed: // a rotation, or another process renewed
			case <-t.C:
			}
			t.Stop()
			continue
		}
		err := k.renew(ctx, move)
		switch cur, _ := m.Current(); {
		case err == nil || ctx.Err() != nil:
			retry = k.RetryWait
			continue
		case move != "" && errors.Is(err, ErrIssuerRefused):
			k.Logger.Warn("org: this machine's organisation name did not follow it to its new relay machine id (the issuer's policy); on the issuer's machine: nfltr org token --rebind "+cur.Subject.CommonName+" --machine-id "+move, "error", err)
			refusedMove, retry = move, k.RetryWait
			continue
		case errors.Is(err, ErrExpired):
			k.Logger.Error("org: this machine was off for more than "+graceDays+"; on the issuer's machine: nfltr org token --rebind "+cur.Subject.CommonName+" --machine-id "+orgid.MachineID(cur)+", then nfltr org join here", "not_after", cur.NotAfter.UTC())
			retry = k.FollowEvery
		case errors.Is(err, ErrIssuerRefused):
			// The issuer answered: no to this certificate (revoked, rebound,
			// or past the grace), not an outage; its reason names the fix.
			k.Logger.Error("org: the organisation issuer refused this machine's renewal; asking again (the refusal names the fix)", "error", err, "not_after", cur.NotAfter.UTC(), "retry_in", retry)
		case !k.Now().Before(cur.NotAfter):
			k.Logger.Warn("org: the organisation issuer does not answer yet; asking again (nothing to do: organisation sessions wait until it answers)", "error", err, "not_after", cur.NotAfter.UTC(), "renews_until", cur.NotAfter.Add(orgpki.RenewGrace).UTC(), "retry_in", retry)
		default:
			k.Logger.Info("org: the organisation issuer does not answer yet; asking again", "error", err, "expires_in", cur.NotAfter.Sub(k.Now()).Round(time.Second), "retry_in", retry)
		}
		t := time.NewTimer(retry)
		select {
		case <-ctx.Done():
		case <-changed: // a CRL or the root taken: the issuer's mailbox answers again
		case <-t.C:
		}
		t.Stop()
		retry = min(retry*2, k.FollowEvery)
	}
}

// ErrExpired: the machine's certificate expired orgpki.RenewGrace ago; the
// issuer renews it no more (Enrol.tla Renews), so only a new token's
// enrolment brings it back: the owner's reissue (a rebind token to the
// name's own machine id), then a join.
var ErrExpired = errors.New("this machine was off for more than " + graceDays + ": the organisation's owner reissues its name (nfltr org token --rebind <name> --machine-id <its id>), then nfltr org join here")

// graceDays is orgpki.RenewGrace in words.
var graceDays = fmt.Sprintf("%d days", int(orgpki.RenewGrace.Hours()/24))

// moveTo is the relay machine id to move the name to: the machine's, when
// it is not its certificate's nor a move the issuer refused; else "".
func (k Keeper) moveTo(refused string) string {
	if k.RelayMachineID == nil {
		return ""
	}
	id := k.RelayMachineID()
	cur, _ := k.Machine.Current()
	if id == "" || id == refused || id == orgid.MachineID(cur) {
		return ""
	}
	return id
}

// renew asks the issuer once for a certificate of a new key, signed by the
// current one (and naming move, the relay machine id to move to, when set),
// under the machine's renewal lock.
func (k Keeper) renew(ctx context.Context, move string) error {
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
	cur, curKey := m.Current()
	if move != "" && move == orgid.MachineID(cur) || move == "" && m.RenewDue(now).After(now) {
		return nil // another process renewed (or moved)
	}
	if !now.Before(cur.NotAfter.Add(orgpki.RenewGrace)) {
		return ErrExpired
	}
	id := randomID()
	key, first, err := renewKey(m.Dir(), hex.EncodeToString(cur.SerialNumber.Bytes()), id)
	if err != nil {
		return err
	}
	csr, err := csrOf(key)
	if err != nil {
		return err
	}
	rr := orgpki.NewRenewRequest(cur.Raw, curKey, csr)
	if move != "" {
		rr = orgpki.NewMoveRequest(cur.Raw, curKey, csr, move)
	}
	a, err := exchange(ctx, k.Mailbox, m.OrgID(), orgpki.Request{ID: id, Renew: &rr}, k.AnswerWait, first)
	if a.Refused != "" {
		_ = os.Remove(filepath.Join(m.Dir(), RenewKeyFile)) // refused: the next renewal is a new one
	}
	if err != nil {
		return err
	}
	if err := m.Install(a.Cert, a.Issuer, a.HostCert, key, k.Now()); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(m.Dir(), RenewKeyFile)) // installed: the machine's key now
	if move != "" && a.MachineKey != nil && k.MachineKey != nil {
		if err := k.takeMachineKey(*a.MachineKey, rr, a, key); err != nil {
			k.Logger.Warn("org: moved to relay machine "+move+" without its A2A key", "error", err)
		}
	}
	return nil
}

// takeMachineKey opens a move's sealed A2A key as the answer to rr (the
// certificate just installed, under the organisation's root) and hands it
// to MachineKey.
func (k Keeper) takeMachineKey(sk orgpki.SealedKey, rr orgpki.RenewRequest, a orgpki.Answer, key ed25519.PrivateKey) error {
	root, err := k.Machine.Root()
	if err != nil {
		return err
	}
	km, err := orgpki.OpenMachineKey(sk, orgpki.MoveKeyID(rr), a.Cert, a.Issuer, root, key, k.Now())
	if err != nil {
		return err
	}
	return k.MachineKey(sk.KeyID, km)
}

// JoinSignIn enrols this device into dir by a person's sign-in
// (orgpki.Issuer.EnrolSignIn; spec/appenrol/AppEnrol.tla EnrolSSO): key is
// the device's organisation key and relayKey its relay key, the two the ID
// token's nonce names (appenrol.SignIn), rule the owner's sign-in rule,
// invite the person's invite (people.go: a first join needs one). The
// organisation is orgID's, checked against pins as Join does; the
// answer is checked for key. Run again with the same key and a token for
// it (invite ""), the issuer certifies the same name again (and moves its
// sign-in on: Reauth).
func JoinSignIn(ctx context.Context, mb Mailbox, dir string, pins Pins, orgID, rule, idToken, invite string, key ed25519.PrivateKey, relayKey crypto.PublicKey, wait time.Duration, now func() time.Time) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	ver, root, rm, cm, err := trust(ctx, mb, orgID, pins, time.Time{}, wait, now)
	if err != nil {
		return nil, err
	}
	// A sign-in names no token, so no root NotBefore: it is held to the
	// pinned root, a rotation since refused, an older root too (Join.tla
	// SignIn, mutant signin-any-recovery; lane SECFIX2, review S9). A
	// sign-in link made after a rotation pins the new root.
	if orgid.Fingerprint(root) != pins.Root {
		return nil, fmt.Errorf("the organisation's root (of %s) is not the pinned one: a sign-in takes only the root its link names (sign in again with a link made since the rotation)", root.NotBefore.UTC().Format(time.RFC3339))
	}
	csr, err := csrOf(key)
	if err != nil {
		return nil, err
	}
	sr, err := orgpki.NewSignInRequest(rule, idToken, csr, relayKey)
	if err != nil {
		return nil, err
	}
	if invite != "" {
		if err := sr.ProveInvite(invite); err != nil {
			return nil, err
		}
	}
	a, err := exchange(ctx, mb, orgID, orgpki.Request{ID: randomID(), SignIn: &sr}, wait)
	if err != nil {
		return nil, err
	}
	if err := orgmachine.Checked(ver, a.Cert, a.Issuer, a.HostCert, key, "", now()); err != nil {
		return nil, fmt.Errorf("the answer: %w", err)
	}
	if err := orgmachine.WriteFiles(dir, orgmachine.Enrolment{Root: rm.Root, Recovery: rm.Recovery, Cert: a.Cert, Issuer: a.Issuer, HostCert: a.HostCert, CRL: cm.CRL, Issuers: rm.Issuers, Key: key}); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(a.Cert)
}
