// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgid

import (
	"context"
	"encoding/json"
	"log/slog"
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
// done: a caller waits for it before removing m's directory.
func Follow(ctx context.Context, mb Mailbox, m *Identity, logger *slog.Logger) {
	followCRL(ctx, mb, m, FollowEvery, time.Now, logger)
}

func followCRL(ctx context.Context, mb Mailbox, m *Identity, every time.Duration, now func() time.Time, logger *slog.Logger) {
	follow(ctx, mb, CRLMailbox(m.OrgID()), every, func(p []byte) error {
		var cm CRLMessage
		if err := json.Unmarshal(p, &cm); err != nil {
			return err
		}
		_, err := m.TakeCRL(cm.CRL, cm.Issuer, now())
		return err
	}, m.Changed, logger)
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
