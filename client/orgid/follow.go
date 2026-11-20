// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"
)

// CRLMailbox is the relay mailbox the organisation's issuer publishes its
// newest CRL to (a CRLMessage, under one replace key). It carries nothing
// secret and the relay can forge none of it: a CRL is the issuer's
// signature, and the issuer is checked to the root.
func CRLMailbox(orgID string) string { return "org." + orgID + ".crl" }

// CRLMessage is the issuer's CRL and its certificate (a verifier needs the
// issuer to check it, and a machine still under the previous issuer has
// not got the new one).
type CRLMessage struct {
	CRL    []byte `json:"crl"`
	Issuer []byte `json:"issuer"`
}

// Mailbox is the relay's mailbox API as Follow uses it
// (*mailboxclient.Client).
type Mailbox interface {
	Pull(ctx context.Context, mailbox string, after uint64, max int, wait time.Duration) ([]mailboxclient.Envelope, string, error)
}

// CRLCopy is the relay's own copy of the organisation's newest
// CRLMessage (mailboxclient.Client.OrgCRL; nil when it holds none): a
// carrier apart from the mailbox service, so a mailbox outage no longer
// lapses the CRL (spec/enrol/CrlCarriers.tla CurrentWithoutMailbox). A
// Mailbox that has it is read for it as well.
type CRLCopy interface {
	OrgCRL(ctx context.Context, orgID string) ([]byte, error)
}

// Timing (transport bounds, not policy).
const (
	// FollowEvery: the backstop, a fresh read of the CRL well before its
	// NextUpdate (the issuer's CRLs last an hour).
	FollowEvery = 10 * time.Minute
	// pollWait: one long-poll (the relay caps it near the same).
	pollWait = 25 * time.Second
	// retryWait: after a failed read, or a message not taken, the wait
	// before the next.
	retryWait = 30 * time.Second
)

// Follow takes the organisation's CRL pushes into m (its Changed cuts the
// sessions a CRL refuses) until ctx ends, a fresh read every FollowEvery:
// a process that opens organisation sessions follows the CRL itself, so a
// revoke reaches its sessions at the push, not at the next Reload of a
// file another process writes. It returns only after its last write is
// done: a caller waits for it before removing m's directory. When mb is
// also a CRLCopy (mailboxclient.Client) it reads the relay's copy too,
// every FollowEvery and whenever m changes; either CRL is taken by the
// same rule (TakeCRL: signed under the trusted root, newer than the one
// held, not lapsed), whichever carrier brought it (CrlCarriers.tla
// copy-rollback, copy-unsigned, stale-copy).
func Follow(ctx context.Context, mb Mailbox, m *Identity, logger *slog.Logger) {
	followCRL(ctx, mb, m, FollowEvery, time.Now, logger)
}

func followCRL(ctx context.Context, mb Mailbox, m *Identity, every time.Duration, now func() time.Time, logger *slog.Logger) {
	// apply(via): the take of one carrier's message (traced with its
	// carrier: CrlCarriers.tla Push, ReadCopy).
	apply := func(via string) func([]byte) error {
		return func(p []byte) error {
			var cm CRLMessage
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
		wg.Go(func() { readCopy(ctx, cp, m.OrgID(), every, apply("copy"), m.Changed, logger) })
	}
	follow(ctx, mb, CRLMailbox(m.OrgID()), every, apply("mailbox"), m.Changed, logger)
	wg.Wait()
}

// readCopy applies the relay's copy of orgID's CRL now, then every every
// and whenever retry's channel closes (m changed: a CRL or a rotation
// taken), until ctx ends; it returns after its last apply. A copy that
// fails to read or is not taken (the one held already, or older) is
// logged at debug: the mailbox's push stays the first carrier.
func readCopy(ctx context.Context, cp CRLCopy, orgID string, every time.Duration, apply func([]byte) error, retry func() <-chan struct{}, logger *slog.Logger) {
	for ctx.Err() == nil {
		var again <-chan struct{}
		if retry != nil {
			again = retry() // before the read: a change meanwhile closes it
		}
		p, err := cp.OrgCRL(ctx, orgID)
		if err == nil && p != nil {
			err = apply(p)
		}
		if err != nil && ctx.Err() == nil {
			logger.Debug("org: the relay's CRL copy not taken", "error", err)
		}
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
		case <-t.C:
		case <-again:
		}
		t.Stop()
	}
}

// follow applies mailbox's newest message whenever it changes: a
// long-poll from the last one seen (the issuer's push wakes it), and a
// fresh read every every (the backstop, Enrol.tla Fetch: a push the relay
// lost or withheld is made good). A message not taken is read afresh
// after retryWait, or at once when retry's channel closes (the machine
// took a rotation: the new issuer's CRL that came first now verifies). A
// failed read is read again at once, then after retryWait while reads keep
// failing: a pull failed by a dead connection (a NAT that changed the
// port) redials at once, so a push lands near the mailbox client's ping
// bound, not retryWait later (TestFollowPullsAgainAtOnceAfterAFailedPull).
// It returns once ctx ends and the message it was taking is taken (its
// write done), never earlier (TestFollowReturnsAfterItsLastWrite).
func follow(ctx context.Context, mb Mailbox, mailbox string, every time.Duration, apply func([]byte) error, retry func() <-chan struct{}, logger *slog.Logger) {
	var cursor uint64
	var fresh time.Time
	failed := false
	for ctx.Err() == nil {
		after := cursor
		if time.Since(fresh) >= every {
			after = 0
		}
		envs, _, err := mb.Pull(ctx, mailbox, after, 0, min(pollWait, every))
		if err != nil {
			if ctx.Err() == nil {
				logger.Warn("org: read failed (read again later)", "mailbox", mailbox, "error", err)
			}
			if failed {
				sleepCtx(ctx, min(retryWait, every))
			}
			failed = true
			continue
		}
		failed = false
		if after == 0 {
			fresh = time.Now()
		}
		if len(envs) == 0 {
			continue
		}
		last := envs[len(envs)-1]
		cursor = last.Seq
		var again <-chan struct{}
		if retry != nil {
			again = retry() // before apply: a rotation taken meanwhile closes it
		}
		if err := apply(last.Payload); err != nil {
			// e.g. a CRL of the new issuer before the rotation that
			// certifies it: read it afresh shortly, or once the rotation
			// is taken.
			logger.Warn("org: message not taken (read again shortly)", "mailbox", mailbox, "error", err)
			fresh = time.Time{}
			t := time.NewTimer(min(retryWait, every))
			select {
			case <-ctx.Done():
			case <-t.C:
			case <-again:
			}
			t.Stop()
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
