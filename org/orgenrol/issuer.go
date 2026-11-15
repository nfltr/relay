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
	"os"
	"path/filepath"
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
	// is not the request's sender's account machine name is refused
	// (wrongMachine).
	MachineOf func(ctx context.Context, name string) (string, error)
	// Now and Wait (one long-poll of the requests): zero is time.Now and
	// serveWait.
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
	// failingSince: the first of the current run of failed maintain
	// rounds (zero while they succeed; maintained).
	failingSince time.Time
}

// rootEvery: the root is published again this often (its message would
// outlive no mailbox TTL: the relay keeps a message at most 7 days).
const rootEvery = 24 * time.Hour

// Run serves until ctx ends; ErrServing when another process serves Dir,
// orgpki.ErrMoved once the directory's log ends in a move's fence.
func (c Service) Run(ctx context.Context) error {
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
	wake, stopWatch := watchDir(c.Dir, logger)
	defer stopWatch()
	var cursor uint64
	for ctx.Err() == nil {
		err := s.maintain(ctx, c.Now())
		if errors.Is(err, orgpki.ErrMoved) {
			return err // the organisation moved to another machine (nfltr org move send)
		}
		if ctx.Err() == nil {
			s.maintained(err, c.Now())
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
				if n := filepath.Base(e.Name); n == orgissuer.CRLFile || n == orgissuer.LogFile {
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
			data, err = s.decide(req, refuse, now)
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
func (s *service) decide(req orgpki.Request, refuse string, now time.Time) ([]byte, error) {
	a := orgpki.Answer{ID: req.ID}
	if refuse != "" {
		a.Refused = refuse
		return json.Marshal(a)
	}
	err := s.with(func(iss *orgpki.Issuer, _ *orgissuer.Store) error {
		var der []byte
		var err error
		switch {
		case req.Enrol != nil:
			der, err = iss.Enrol(*req.Enrol, now)
		case req.Renew != nil:
			der, err = iss.Renew(*req.Renew, now)
		default:
			err = errors.New("neither an enrolment nor a renewal")
		}
		if err != nil {
			a.Refused = err.Error()
			return nil
		}
		a.Cert, a.Issuer = der, iss.Cert().Raw
		// The host certificate (nfltr cat serve --ssh) restates the certificate
		// just logged, so it is never refused; only a failed random read
		// errs, as the certificate's own signature would.
		if a.HostCert, err = iss.HostCert(der, now); err != nil {
			return err
		}
		if req.Enrol != nil && s.MachineKey != nil {
			// The certificate is issued: a key not sealed (an id issued
			// before is not sealed again) leaves the answer without it, never unanswered.
			if a.MachineKey, err = s.sealMachineKey(iss, req.Enrol.TokenID, der, now); err != nil {
				s.Logger.Warn("org issuer: enrolled without its A2A key", "error", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(a)
}

// sealMachineKey is the enrolled machine key sealed to its
// certificate's key; none for a certificate without a machine id.
func (s *service) sealMachineKey(iss *orgpki.Issuer, tokenID string, der []byte, now time.Time) (*orgpki.SealedKey, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil || orgid.MachineID(c) == "" {
		return nil, err
	}
	keyID, km, err := s.MachineKey(orgid.MachineID(c), c.Subject.CommonName, now)
	if err != nil {
		return nil, fmt.Errorf("the machine's A2A key: %w", err)
	}
	k, err := iss.SealMachineKey(tokenID, der, keyID, km)
	return &k, err
}

// maintain signs a CRL when none is current (none yet, a third of its
// life left, or signed by another issuer than the current: a rotation),
// then publishes the root and the CRL the relay does not hold.
func (s *service) maintain(ctx context.Context, now time.Time) error {
	var root, rec, crl, issuer []byte
	var crlErr error // ErrIssuerExpired: the root is still published
	err := s.with(func(iss *orgpki.Issuer, st *orgissuer.Store) error {
		der, err := st.ReadCRL()
		if err != nil {
			return err
		}
		_, next := iss.LastCRL()
		if der == nil || iss.CRLDue() || next.Sub(now) <= orgpki.CRLLife/3 || !signedBy(der, iss.Cert()) {
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
		root, rec, crl, issuer = iss.Root().Raw, iss.Recovery().Raw, der, iss.Cert().Raw
		return nil
	})
	if err != nil {
		return err
	}
	if !bytes.Equal(root, s.pubRoot) || now.Sub(s.pubRootAt) >= rootEvery {
		if err := s.publish(ctx, orgpki.RootMailbox(s.org), orgpki.RootMessage{Root: root, Recovery: rec}); err != nil {
			return fmt.Errorf("root: %w", err)
		}
		s.pubRoot, s.pubRootAt = root, now
	}
	if crlErr != nil {
		return crlErr
	}
	if !bytes.Equal(crl, s.pubCRL) || !bytes.Equal(issuer, s.pubCRLIssuer) {
		if err := s.publish(ctx, orgid.CRLMailbox(s.org), orgid.CRLMessage{CRL: crl, Issuer: issuer}); err != nil {
			return fmt.Errorf("CRL: %w", err)
		}
		s.pubCRL, s.pubCRLIssuer = crl, issuer
	}
	return nil
}

func signedBy(crl []byte, issuer *x509.Certificate) bool {
	c, err := x509.ParseRevocationList(crl)
	return err == nil && c.CheckSignatureFrom(issuer) == nil
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
