// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/nfltr/relay/client/mailboxclient"
	"github.com/nfltr/relay/client/orgid"

	"github.com/nfltr/relay/org/internal/orgfiles"
	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgpki"
)

// serveWait: one long-poll of the requests; also the backstop for a CRL
// another process wrote (nfltr org revoke, an account-revocation tie-in)
// whose file-change notice was lost (watchDir): that write is published at
// once on its notice, at the latest at the next round
// (spec/enrol/RevokePush.tla EventBound, BackstopBound).
const serveWait = 10 * time.Second

// copyEvery: the issuer puts the relay's copy of its CRL again this often
// (and at once when the CRL changes): the copy is in the relay's process
// and a restart loses it. CrlCarriers.tla CurrentWithoutMailbox needs
// copyEvery + orgid.FollowEvery under orgid.CRLWarnAge - orgpki.CRLEvery
// (QuietWhileIssuerUp).
const copyEvery = 5 * time.Minute

// CRLCopyWriter is a Mailbox that also keeps the relay's own copy of the
// organisation's CRL (mailboxclient.Client.PutOrgCRL; relay-server
// /api/v1/org-crl/<org id>): the CRL's carrier apart from the mailbox
// service, which members read too (orgid.CRLCopy). The issuer puts the
// same orgid.CRLMessage it publishes.
type CRLCopyWriter interface {
	PutOrgCRL(ctx context.Context, orgID string, msg []byte) error
}

// StatusCopyWriter is a Mailbox that also keeps the relay's copy of the
// organisation's signed status (mailboxclient.Client.PutOrgStatus;
// relay-server /api/v1/org-status/<org id>; nfltr
// docs/decisions/org-dashboard-2026-11-21.md): what the dashboard and
// `nfltr org status --relay` read. The issuer puts it when it changes and
// every few minutes (the copy is in the relay's process).
type StatusCopyWriter interface {
	PutOrgStatus(ctx context.Context, orgID string, msg []byte) error
}

// sinkClient posts to an URL audit sink (ExportAudit).
var sinkClient = &http.Client{Timeout: 30 * time.Second}

// serveLock: the file a Service holds while it serves its directory.
const serveLock = "serve.lock"

// Serving is whether a process serves the issuer directory dir now (a
// Service holds its lock): nfltr org status.
func Serving(dir string) bool {
	unlock, err := orgfiles.TryLock(filepath.Join(dir, serveLock))
	if err != nil {
		return errors.Is(err, orgfiles.ErrLocked)
	}
	unlock()
	return false
}

// ErrServing: another process serves this issuer directory already.
var ErrServing = errors.New("the organisation's issuer is served by another process already")

// ShareRelease is the mailbox declaration (relay-server
// mailbox.ShareRelease, on an ack) by which a machine gives its hold of a
// shared mailbox up; on a hold that is not the caller's it changes
// nothing.
const ShareRelease = "release"

// HoldServeLock takes the serve lock of the issuer directory dir, waiting
// until ctx ends for a Service serving it to stop (one stops at the move's
// fence): nfltr org move send gives the holds up only while it holds it,
// so no publish read before the fence lands after the release
// (spec/orgmove/OrgHolds.tla Lock, OldCannotWrite). ErrServing when ctx
// ends first.
func HoldServeLock(ctx context.Context, dir string) (unlock func(), err error) {
	for {
		unlock, err := orgfiles.TryLock(filepath.Join(dir, serveLock))
		if !errors.Is(err, orgfiles.ErrLocked) {
			if err == nil {
				traceHold("lock", "", dir)
			}
			return unlock, err
		}
		select {
		case <-ctx.Done():
			return nil, ErrServing
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// ReleaseHolds gives this machine's holds of the organisation's shared
// mailboxes up (mb declares ShareRelease): the root, CRL and answers
// broadcasts and the enrol drop box stay, with their messages, vacant
// until the next issuer's holder declaration takes them (relay-server
// spec/Reach.tla GiveUp; spec/orgmove/OrgHolds.tla Release). Run again,
// it changes nothing.
func ReleaseHolds(ctx context.Context, mb Mailbox, orgID string) error {
	for _, name := range []string{orgpki.RootMailbox(orgID), orgid.CRLMailbox(orgID), orgpki.AnswersMailbox(orgID), orgpki.EnrolMailbox(orgID)} {
		if err := mb.Ack(ctx, name, 0); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	traceHold("release", orgID, "")
	return nil
}

// Service is the issuer's mailbox service over the issuer directory Dir
// (orgissuer): it answers each request under the directory's lock
// (Enrol.tla Issue: the decision is the log's as of now), signs the next
// CRL before NextUpdate (Republish), and publishes the CRL and the root
// whenever they change (the push). One per directory.
type Service struct {
	Mailbox Mailbox
	Dir     string
	Logger  *slog.Logger
	// MachineKey, when set, makes the machine key of an enrolled machine id
	// (a new id only); the answer carries it sealed
	// to the certified key (orgpki.SealMachineKey).
	MachineKey func(machineID, name string, now time.Time) (keyID string, key []byte, err error)
	// MachineOf, when set, is the machine id of a machine name of the
	// relay account ("" when it has none): an enrolment whose token's name
	// is not the request's sender's account machine name is refused.
	MachineOf func(ctx context.Context, name string) (string, error)
	// Now and Wait (one long-poll of the requests): zero is time.Now and
	// 10 s.
	Now  func() time.Time
	Wait time.Duration
}

type service struct {
	Service
	org string
	// The issuer as last replayed, and the log's size then: replayed
	// again only when another process wrote the log.
	iss     *orgpki.Issuer
	logSize int64
	// What the relay holds (published by this service).
	pubRoot, pubCRL, pubCRLIssuer []byte
	pubRootAt                     time.Time
	// The CRL last put on the relay's copy, and when (putCopy).
	copyCRL []byte
	copyAt  time.Time
	// The status last put on the relay's copy (its body without At), and
	// when (putStatus).
	copyStatus   []byte
	copyStatusAt time.Time
	// pubs: the round's publishes since its read, -1 before it read
	// (the OrgHolds trace's write line).
	pubs int
	// relayLost: a read of the requests failed since the last status put
	// (the relay unreachable or restarted): the next round puts it at once.
	relayLost bool
	// failingSince: the first of the current run of failed maintain
	// rounds (zero while they succeed; maintained).
	failingSince time.Time
}

// rootEvery: the root is published again this often (its message would
// outlive no mailbox TTL: the relay keeps a message at most 7 days).
const rootEvery = 24 * time.Hour

// Run serves until ctx ends; ErrServing when another process serves Dir,
// orgpki.ErrMoved once the directory's log ends in a move's fence.
func (c Service) Run(ctx context.Context) (err error) {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Wait <= 0 {
		c.Wait = serveWait
	}
	mb, logger := c.Mailbox, c.Logger
	unlock, err := orgfiles.TryLock(filepath.Join(c.Dir, serveLock))
	if errors.Is(err, orgfiles.ErrLocked) {
		return ErrServing
	}
	if err != nil {
		return err
	}
	defer unlock()
	// A stopped server's record of a failing publish: this one records its own.
	_ = os.Remove(filepath.Join(c.Dir, publishFailingFile))
	if err := os.MkdirAll(filepath.Join(c.Dir, spoolDir), 0o700); err != nil { // nosemgrep: incorrect-default-permission -- the issuer's private directory, owner only (0700)
		return err
	}
	s := &service{Service: c}
	if err := s.with(func(iss *orgpki.Issuer, _ *orgissuer.Store) error { s.org = iss.OrgID(); return nil }); err != nil {
		return err
	}
	traceHold("start", s.org, c.Dir)
	defer func() { traceHoldEnd(s.org, c.Dir, err) }() // before unlock: the lock is free after it
	wake, stopWatch := watchDir(c.Dir, logger)
	defer stopWatch()
	var cursor uint64
	for ctx.Err() == nil {
		s.pubs = -1
		err := s.maintain(ctx, c.Now())
		if s.pubs >= 0 {
			traceHoldWrite(s.org, c.Dir, s.pubs)
		}
		if errors.Is(err, orgpki.ErrMoved) {
			return err // the organisation moved to another machine (nfltr org move send)
		}
		if ctx.Err() == nil {
			s.maintained(err, c.Now())
			if _, err := ExportAudit(ctx, c.Dir, sinkClient); err != nil && ctx.Err() == nil {
				logger.Warn("org issuer: the audit sink did not take the sessions (again next round; nothing is lost)", "error", err)
			}
		}
		// The round: a notice ends it at once, and the loop maintains
		// (RevokePush.tla Read: a notice taken before the read; one that
		// came during the maintain is still in wake).
		pctx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-wake:
				cancel()
			case <-pctx.Done():
			}
		}()
		envs, _, err := mb.Pull(pctx, orgpki.EnrolMailbox(s.org), cursor, 0, c.Wait)
		woken := pctx.Err() != nil && ctx.Err() == nil
		cancel()
		if err != nil {
			if ctx.Err() == nil && !woken {
				s.relayLost = true
				logger.Warn("org issuer: requests not read (again shortly)", "error", err)
				select {
				case <-ctx.Done():
				case <-wake:
				case <-time.After(c.Wait):
				}
			}
			continue
		}
		done := cursor
		var spooled []string
		for _, e := range envs {
			f, err := s.answer(ctx, e, c.Now())
			if errors.Is(err, orgpki.ErrMoved) {
				return err // unanswered and unacknowledged: the new machine answers it
			}
			if err != nil {
				logger.Warn("org issuer: answer not posted (the request is read again)", "error", err)
				break
			}
			done, spooled = e.Seq, append(spooled, f)
		}
		if done > cursor {
			cursor = done
			if err := mb.Ack(ctx, orgpki.EnrolMailbox(s.org), done); err != nil {
				if ctx.Err() == nil {
					logger.Warn("org issuer: requests not acknowledged", "error", err)
				}
				continue
			}
			for _, f := range spooled {
				_ = os.Remove(f) // acknowledged: never read again
			}
		}
	}
	return nil
}

// watchDir notices another process's write of the issuer's CRL or log
// into dir (nfltr org revoke, the account-revocation tie-in, a rotation):
// one value on wake per burst of writes, kept until taken (RevokePush.tla
// Revoke; mutant clear-wake-after-publish drops one that comes during a
// maintain). Without a watcher (none starts: no inotify or kqueue left)
// wake is nil and the round is the only path, as it is the backstop for
// a lost notice (LoseWake). An overflow counts as a notice.
func watchDir(dir string, logger *slog.Logger) (wake <-chan struct{}, stop func()) {
	w, err := fsnotify.NewWatcher()
	if err == nil {
		if err = w.Add(dir); err != nil {
			_ = w.Close()
		}
	}
	if err != nil {
		logger.Warn("org issuer: no file-change notices; a revoke is published at the next round", "every", serveWait, "error", err)
		return nil, func() {}
	}
	c := make(chan struct{}, 1)
	notify := func() {
		select {
		case c <- struct{}{}:
		default: // one is waiting already
		}
	}
	go func() {
		for {
			select {
			case e, ok := <-w.Events:
				if !ok {
					return
				}
				switch filepath.Base(e.Name) {
				case orgissuer.CRLFile, orgissuer.LogFile:
					traceNotice(dir)
					notify()
				case orgissuer.IssuersFile: // the root's CRL of issuers: published with the root (no RevokePush.tla step)
					notify()
				}
			case _, ok := <-w.Errors:
				if !ok {
					return
				}
				notify()
			}
		}
	}()
	return c, func() { _ = w.Close() }
}

// with runs f on the issuer under the directory's lock.
func (s *service) with(f func(*orgpki.Issuer, *orgissuer.Store) error) error {
	st, err := orgissuer.Lock(s.Dir)
	if err != nil {
		return err
	}
	defer st.Unlock()
	size := func() int64 {
		fi, err := os.Stat(st.Path(orgissuer.LogFile))
		if err != nil {
			return -1
		}
		return fi.Size()
	}
	if s.iss == nil || size() != s.logSize {
		if s.iss, err = st.Open(); err != nil {
			return err
		}
	}
	err = f(s.iss, st)
	s.logSize = size()
	return err
}

// answer decides one request and posts the answer under the request's id.
// The decision is kept in the spool (spoolDir) until the request is
// acknowledged, so a request read again (a failed post or ack, a crash) is
// answered as it was: an enrolment redeems its token once. It returns the
// spool file, "" for a payload that is not a request.
func (s *service) answer(ctx context.Context, e mailboxclient.Envelope, now time.Time) (string, error) {
	var req orgpki.Request
	if err := json.Unmarshal(e.Payload, &req); err != nil || req.ID == "" {
		return "", nil // not a request: nothing to answer
	}
	sum := sha256.Sum256([]byte(req.ID))
	f := filepath.Join(s.Dir, spoolDir, hex.EncodeToString(sum[:]))
	data, err := os.ReadFile(f) // #nosec G304 -- the issuer's own spool, named by a hash
	if os.IsNotExist(err) {
		var refuse string
		if refuse, err = s.wrongMachine(ctx, req, e.Sender); err == nil {
			data, err = s.decide(ctx, req, refuse, now)
		}
		if err == nil {
			err = orgfiles.Write(f, data, 0o600)
		}
	}
	if err != nil {
		return "", err
	}
	_, err = s.Mailbox.Append(ctx, orgpki.AnswersMailbox(s.org), data, mailboxclient.AppendOptions{IdempotencyKey: req.ID, ContentType: "application/json", TTL: answerTTL})
	return f, err
}

// spoolDir: answers decided and not yet acknowledged, in the issuer
// directory.
const spoolDir = "answers"

// wrongMachine is the refusal of an enrolment whose token's name is not
// the account machine name of the machine the relay says posted it
// (the strict rule): the certificate's name would route to another machine, or to
// none, and a client dialling <machine>.<agent> would be refused (exit 7).
// It is decided before the token is redeemed. The relay's word decides
// nothing the models protect: it can only refuse, as it can by not
// carrying the request.
func (s *service) wrongMachine(ctx context.Context, req orgpki.Request, sender string) (string, error) {
	if r := req.Renew; r != nil && r.MachineID != "" && senderMachine(sender) != r.MachineID {
		return fmt.Sprintf("a move to relay machine %s posted by %s: only that machine asks to move a name to it", r.MachineID, cmp.Or(sender, "unknown")), nil
	}
	if e := req.Enrol; e != nil && e.MachineID != "" && senderMachine(sender) != e.MachineID { // Join.tla Relabel
		return fmt.Sprintf("an enrolment stating relay machine %s posted by %s: only that machine states its id", e.MachineID, cmp.Or(sender, "unknown")), nil
	}
	if req.Enrol == nil || s.MachineOf == nil {
		return "", nil
	}
	var name string
	if err := s.with(func(iss *orgpki.Issuer, _ *orgissuer.Store) error {
		name = iss.TokenName(req.Enrol.TokenID)
		return nil
	}); err != nil || name == "" {
		return "", err
	}
	id, err := s.MachineOf(ctx, name)
	if err != nil {
		return "", err
	}
	from := senderMachine(sender)
	if id == "" {
		return fmt.Sprintf("the token is for %s, but the account has no machine named %s, and machine %s posted the request: an organisation machine's name is its account machine's name; give this machine a key of its own named %s (one key per machine), or make a new token for this machine's own name (nfltr machines lists them)", name, name, cmp.Or(from, sender, "unknown"), name), nil
	}
	if from != id {
		return fmt.Sprintf("the token is for %s, machine %s of the account, but machine %s posted the request: enrol each machine under its name in the account (nfltr machines lists them); make a new token, for %s to join on %s or for this machine's own name", name, id, cmp.Or(from, sender, "unknown"), name, name), nil
	}
	return "", nil
}

// movePolicy admits moving a name to a relay machine id when that id is
// the issuer's account machine of that name (MachineOf; Enrol.tla Move,
// MoveOnlyOwnAccount): the default for the account that holds the
// issuer. nil (no MachineOf): only a rebind token moves a name. With an
// A2A root (MachineKey) the move's answer carries the new id's key
// (decide; nfltr spec/proverif a2a_keytransfer.pv Move, lane CERTGAPS).
func (s *service) movePolicy(ctx context.Context) orgpki.MovePolicy {
	if s.MachineOf == nil {
		return nil
	}
	return func(name, id string) error {
		got, err := s.MachineOf(ctx, name)
		switch {
		case err != nil:
			return err
		case got != id:
			return fmt.Errorf("the issuer's relay account has no machine %s named %s", id, name)
		}
		return nil
	}
}

// senderMachine is the machine id of a mailbox sender the relay asserts
// (m-<id> or m-<id>-<agent>), "" for another kind.
func senderMachine(sender string) string {
	rest, ok := strings.CutPrefix(sender, "m-")
	if !ok {
		return ""
	}
	id, _, _ := strings.Cut(rest, "-")
	return "m-" + id
}

// decide answers req under the directory's lock; refuse, when set, is the
// answer's refusal (nothing is redeemed).
func (s *service) decide(ctx context.Context, req orgpki.Request, refuse string, now time.Time) ([]byte, error) {
	a := orgpki.Answer{ID: req.ID}
	if refuse != "" {
		a.Refused = refuse
		return json.Marshal(a)
	}
	err := s.with(func(iss *orgpki.Issuer, st *orgissuer.Store) error {
		var der []byte
		var err error
		switch {
		case req.Order != nil: // the root's order (OrgDash.tla Apply, GroupMirror.tla Move): no certificate
			switch o, err := iss.ApplyOrder(*req.Order, now); {
			case err != nil:
				a.Refused = err.Error()
			case o.Act == orgpki.ActMoveOrder:
				a.Moved = o.Name
			default:
				a.Revoked = o.Name
			}
			return nil
		case req.Policy != nil: // the root's access policy (GroupMirror.tla RuleApply): no certificate
			if a.Policy, err = iss.TakePolicy(*req.Policy, now); err != nil {
				a.Refused = err.Error()
			}
			return nil
		case req.Grant != nil: // a grant act (Grant.tla Request, Sign, Deny, Revoke): the grant rides the status
			r, err := iss.ApplyGrant(*req.Grant, now)
			if err != nil {
				a.Refused = err.Error()
			} else {
				a.Grant = &r
			}
			return nil
		case req.Audit != nil: // a machine's session audit lines (audit.go): no certificate
			r, err := takeAudit(s.Dir, iss, *req.Audit, now)
			if err != nil {
				a.Refused = err.Error()
			} else {
				a.Audit = &r
			}
			return nil
		case req.People != nil: // the root's or an admin's act on the roster (People.tla): no certificate
			r, err := iss.ApplyPeople(*req.People, now)
			if err != nil {
				a.Refused = err.Error()
			} else if r.Person != "" {
				a.Removal = &r
			}
			return nil
		case req.IssuerRenewal != nil: // the root's renewal (OrgDash.tla Apply): InstallRenewal refuses an old one
			if err := iss.InstallRenewal(*req.IssuerRenewal, now); err != nil {
				a.Refused = err.Error()
				return nil
			}
			a.Issuer = iss.Cert().Raw
			if req.IssuerRenewal.Issuers != nil {
				return st.TakeIssuers(iss.Root(), req.IssuerRenewal.Issuers)
			}
			return nil
		case req.Enrol != nil:
			iss.SetMovePolicy(s.movePolicy(ctx)) // binds the join's stated id (Join.tla Issue)
			der, err = iss.Enrol(*req.Enrol, now)
		case req.Renew != nil:
			iss.SetMovePolicy(s.movePolicy(ctx))
			der, err = iss.Renew(*req.Renew, now)
		case req.SignIn != nil:
			// ponytail: fetches the IdP's keys (once per IdP, cached) under the directory's lock
			der, err = iss.EnrolSignIn(ctx, *req.SignIn, now)
		default:
			err = errors.New("neither an enrolment, a renewal, a sign-in, an order, a people act, a grant act nor the root's renewal")
		}
		if err != nil {
			a.Refused, a.SignInEnded = err.Error(), errors.Is(err, orgpki.ErrSignInEnded)
			return nil
		}
		a.Cert, a.Issuer = der, iss.Cert().Raw
		if req.Enrol != nil {
			a.TokenMAC = iss.AnswerMAC(req.Enrol.TokenID, der, a.Issuer) // Join.tla JoinedByIssuer
		}
		// The host certificate (nfltr cat serve --ssh) restates the certificate
		// just logged, so it is never refused; only a failed random read
		// errs, as the certificate's own signature would.
		if a.HostCert, err = iss.HostCert(der, now); err != nil {
			return err
		}
		// The certificate is issued: a key not sealed (an id issued
		// before is not sealed again) leaves the answer without it, never unanswered.
		switch {
		case s.MachineKey == nil:
		case req.Enrol != nil:
			if a.MachineKey, err = s.sealMachineKey(der, now, func(keyID string, km []byte) (orgpki.SealedKey, error) {
				return iss.SealMachineKey(req.Enrol.TokenID, der, keyID, km)
			}); err != nil {
				s.Logger.Warn("org issuer: enrolled without its A2A key", "error", err)
			}
		case req.Renew != nil && req.Renew.MachineID != "" && iss.NameOfMachine(req.Renew.MachineID) != "":
			// a move (the renewal's certificate is of the request's id): the
			// new id's key, its store entry replacing the old id's (a2akeys
			// RebindMachineKey; a2a_keytransfer.pv Move)
			if a.MachineKey, err = s.sealMachineKey(der, now, func(keyID string, km []byte) (orgpki.SealedKey, error) {
				return iss.SealMovedKey(*req.Renew, der, keyID, km)
			}); err != nil {
				s.Logger.Warn("org issuer: moved without its A2A key", "error", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(a)
}

// sealMachineKey is the machine key of an enrolled or moved certificate
// sealed (by seal) to its key; none for a certificate without a machine id.
func (s *service) sealMachineKey(der []byte, now time.Time, seal func(keyID string, km []byte) (orgpki.SealedKey, error)) (*orgpki.SealedKey, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil || orgid.MachineID(c) == "" {
		return nil, err
	}
	keyID, km, err := s.MachineKey(orgid.MachineID(c), c.Subject.CommonName, now)
	if err != nil {
		return nil, fmt.Errorf("the machine's A2A key: %w", err)
	}
	k, err := seal(keyID, km)
	return &k, err
}

// maintain signs a CRL when none is current (none yet, one orgpki.CRLEvery
// old, or signed by another issuer than the current: a rotation),
// then publishes the root and the CRL the relay does not hold.
func (s *service) maintain(ctx context.Context, now time.Time) error {
	var root, rec, crl, issuer, issuers []byte
	var rootCert *x509.Certificate
	var crlErr error // ErrIssuerExpired: the root is still published
	err := s.with(func(iss *orgpki.Issuer, st *orgissuer.Store) error {
		der, err := st.ReadCRL()
		if err != nil {
			return err
		}
		_, next := iss.LastCRL()
		if der == nil || iss.CRLDue() || next.Sub(now) <= orgpki.CRLLife-orgpki.CRLEvery || !signedBy(der, iss.Cert()) {
			der, err = iss.CRL(now)
			switch {
			case errors.Is(err, orgpki.ErrIssuerExpired):
				crlErr = fmt.Errorf("CRL: %w", err)
			case err != nil:
				return err
			default:
				if err := st.WriteCRL(der, iss.Cert()); err != nil {
					return err
				}
			}
		}
		if issuers, err = st.ReadIssuers(); err != nil {
			return err
		}
		rootCert, root, rec, crl, issuer = iss.Root(), iss.Root().Raw, iss.Recovery().Raw, der, iss.Cert().Raw
		traceRead(s.Dir, der) // under the lock (RevokePush.tla Read)
		traceHold("read", s.org, s.Dir)
		s.pubs = 0
		return nil
	})
	if err != nil {
		return err
	}
	if crlErr == nil {
		s.putCopy(ctx, crl, issuer, now) // before the mailbox: its outage must not hold the copy back
	}
	if pub := slices.Concat(root, issuers); !bytes.Equal(pub, s.pubRoot) || now.Sub(s.pubRootAt) >= rootEvery {
		// The owner's machine may have published a newer CRL of issuers
		// itself (a revoke this issuer did not publish): kept, not
		// overwritten.
		if data, err := latest(ctx, s.Mailbox, orgpki.RootMailbox(s.org), 0); err == nil && newerIssuers(data, rootCert, issuers) != nil {
			err := s.with(func(_ *orgpki.Issuer, st *orgissuer.Store) error {
				held, err := st.ReadIssuers()
				if n := newerIssuers(data, rootCert, held); err == nil && n != nil {
					issuers, err = n, st.WriteIssuers(n)
				}
				return err
			})
			if err != nil {
				return err
			}
		}
		if err := s.publish(ctx, orgpki.RootMailbox(s.org), orgpki.RootMessage{Root: root, Recovery: rec, Issuers: issuers}); err != nil {
			return fmt.Errorf("root: %w", err)
		}
		s.pubs++
		s.pubRoot, s.pubRootAt = slices.Concat(root, issuers), now
	}
	s.putStatus(ctx, now, s.relayLost) // at once when the relay is back (GroupMirror.tla Reput); a new CRL changes the status (its CRL), so it is put with it (Sign)
	if crlErr != nil {
		return crlErr
	}
	if !bytes.Equal(crl, s.pubCRL) || !bytes.Equal(issuer, s.pubCRLIssuer) {
		if err := s.publish(ctx, orgid.CRLMailbox(s.org), orgid.CRLMessage{CRL: crl, Issuer: issuer}); err != nil {
			return fmt.Errorf("CRL: %w", err)
		}
		s.pubs++
		tracePublish(s.Dir, crl)
		s.pubCRL, s.pubCRLIssuer = crl, issuer
	}
	return nil
}

// newerIssuers is the root's CRL of issuers in a RootMessage payload when
// root signed it and its Number is above held's (nil held: any); nil
// otherwise. The relay can forge none of it: it is the root's signature.
func newerIssuers(payload []byte, root *x509.Certificate, held []byte) []byte {
	var rm orgpki.RootMessage
	if json.Unmarshal(payload, &rm) != nil {
		return nil
	}
	n := issuersNumber(rm.Issuers, root)
	if h := issuersNumber(held, root); n == nil || (h != nil && n.Cmp(h) <= 0) {
		return nil
	}
	return rm.Issuers
}

// issuersNumber is the Number of der, a CRL of issuers root signed; nil
// when it is not one.
func issuersNumber(der []byte, root *x509.Certificate) *big.Int {
	if der == nil {
		return nil
	}
	c, err := x509.ParseRevocationList(der)
	if err != nil || c.CheckSignatureFrom(root) != nil {
		return nil
	}
	return c.Number
}

func signedBy(crl []byte, issuer *x509.Certificate) bool {
	c, err := x509.ParseRevocationList(crl)
	return err == nil && c.CheckSignatureFrom(issuer) == nil
}

// putCopy puts the CRL on the relay's copy when the Mailbox keeps one,
// when it changed or copyEvery passed since the last attempt (a refusal is
// tried again then: a relay without the copy is not asked every round). A
// failure is logged; the mailbox's publish and its alarm are unchanged.
func (s *service) putCopy(ctx context.Context, crl, issuer []byte, now time.Time) {
	w, ok := s.Mailbox.(CRLCopyWriter)
	if !ok || (bytes.Equal(crl, s.copyCRL) && now.Sub(s.copyAt) < copyEvery) {
		return
	}
	s.copyCRL, s.copyAt = crl, now
	tracePut(s.Dir, crl) // before the put: a member's read may follow it at once
	data, err := json.Marshal(orgid.CRLMessage{CRL: crl, Issuer: issuer})
	if err == nil {
		err = w.PutOrgCRL(ctx, s.org, data)
	}
	if err != nil && ctx.Err() == nil {
		s.Logger.Warn("org issuer: the relay's copy of the CRL not kept (tried again within "+copyEvery.String()+"; members still read the mailbox)", "error", err)
	}
}

// putStatus puts the issuer's signed status on the relay's copy when the
// Mailbox keeps one, when it changed (its At aside: a new CRL is a change),
// copyEvery passed or force (the relay was unreachable: its copy, held in
// process memory, may be gone; mutant no-reput-on-reconnect). A failure is logged (a relay that holds another
// organisation for this account refuses it: one organisation per
// account).
func (s *service) putStatus(ctx context.Context, now time.Time, force bool) {
	w, ok := s.Mailbox.(StatusCopyWriter)
	if !ok {
		return
	}
	var st orgpki.SignedStatus
	err := s.with(func(iss *orgpki.Issuer, _ *orgissuer.Store) (err error) {
		st, err = iss.SignedStatus(now)
		return err
	})
	key := statusContent(st.Body)
	if err != nil || (!force && bytes.Equal(key, s.copyStatus) && now.Sub(s.copyStatusAt) < copyEvery) {
		return
	}
	s.copyStatus, s.copyStatusAt = key, now
	data, err := json.Marshal(st)
	if err == nil {
		err = w.PutOrgStatus(ctx, s.org, data)
	}
	if err == nil {
		s.relayLost = false
	}
	if err != nil && ctx.Err() == nil {
		s.Logger.Warn("org issuer: the relay's copy of the organisation status not kept (tried again within "+copyEvery.String()+")", "error", err)
	}
}

// statusContent is a status body without its At: what changed means.
func statusContent(body []byte) []byte {
	var st orgpki.Status
	if json.Unmarshal(body, &st) != nil {
		return nil
	}
	st.At = time.Time{}
	b, _ := json.Marshal(st)
	return b
}

// publish keeps msg as mailbox's one message (replace key); the append
// wakes the mailbox's long-polls.
func (s *service) publish(ctx context.Context, mailbox string, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = s.Mailbox.Append(ctx, mailbox, data, mailboxclient.AppendOptions{ReplaceKey: "current", ContentType: "application/json"})
	return err
}
