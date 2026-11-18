// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package orgenrol carries enrolment, renewal, the CRL and the root over
// the relay's mailboxes (spec/enrol/Enrol.tla Request, Issue, Install,
// Fetch, TakeRoot):
//
//   - the machine's side: Join (a token's enrolment), and Keep, which
//     renews at 2/3 of the certificate's lifetime or at once after a
//     rotation, and follows the CRL and the root (the issuer's push wakes
//     a parked long-poll; a fresh read every FollowEvery is the backstop);
//   - the issuer's side: Serve, which answers requests under the issuer's
//     lock, signs the next CRL before NextUpdate and publishes the CRL and
//     the root whenever they change.
//
// The relay carries everything and can forge none of it (spec/proverif/
// enrol.pv): requests are bound to a token or signed by the current key,
// answers and CRLs are the issuer's signatures, the root is pinned or the
// recovery key's. A machine takes only an answer for the key it made last,
// under the root it trusts (orgmachine.Checked).
package orgenrol

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"

	"github.com/nfltr/relay/org/orgpki"
)

// Mailbox is the relay's mailbox API as orgenrol uses it
// (mailboxclient.Client).
type Mailbox interface {
	Append(ctx context.Context, mailbox string, payload []byte, o mailboxclient.AppendOptions) (mailboxclient.Appended, error)
	Pull(ctx context.Context, mailbox string, after uint64, max int, wait time.Duration) ([]mailboxclient.Envelope, string, error)
	Ack(ctx context.Context, mailbox string, through uint64) error
}

// Timing (transport bounds, not policy).
const (
	// FollowEvery: the backstop, a fresh read of the CRL and the root well
	// before the CRL's NextUpdate (orgpki.CRLLife).
	FollowEvery = 10 * time.Minute
	// pollWait: one long-poll (the relay caps it near the same).
	pollWait = 25 * time.Second
	// retryWait: after a failed read or a failed renewal, the wait before
	// the next.
	retryWait = 30 * time.Second
	// AnswerWait: how long a machine waits for the answer to one request;
	// then it asks again with a new key (Enrol.tla Request after a loss).
	AnswerWait = 2 * time.Minute
	// answerTTL: how long the relay keeps an answer.
	answerTTL = time.Hour
)

// exchange posts req and waits up to wait for its answer, or one to an
// earlier request of the same key (also), by id: a relay can relabel an
// answer, which the caller's check of the certificate refuses. A refusal
// is an error carrying the issuer's reason.
func exchange(ctx context.Context, mb Mailbox, orgID string, req orgpki.Request, wait time.Duration, also ...string) (orgpki.Answer, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return orgpki.Answer{}, err
	}
	if _, err := mb.Append(ctx, orgpki.EnrolMailbox(orgID), payload, mailboxclient.AppendOptions{IdempotencyKey: req.ID, ContentType: "application/json", TTL: answerTTL}); err != nil {
		return orgpki.Answer{}, fmt.Errorf("post the request: %w", err)
	}
	return answerOf(ctx, mb, orgID, append([]string{req.ID}, also...), wait)
}

// answerOf is the first answer the relay holds to any request of ids.
func answerOf(ctx context.Context, mb Mailbox, orgID string, ids []string, wait time.Duration) (orgpki.Answer, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var cursor uint64
	for {
		envs, _, err := member(mb).Pull(ctx, orgpki.AnswersMailbox(orgID), cursor, 0, min(pollWait, wait))
		if ctx.Err() != nil {
			return orgpki.Answer{}, fmt.Errorf("no answer from the organisation's issuer within %s (is the issuer running: nfltr node or nfltr org serve on the issuer's machine?)", wait)
		}
		if err != nil {
			return orgpki.Answer{}, fmt.Errorf("read the answers: %w", err)
		}
		for _, e := range envs {
			cursor = e.Seq
			var a orgpki.Answer
			if json.Unmarshal(e.Payload, &a) != nil || !slices.Contains(ids, a.ID) {
				continue
			}
			if a.SignInEnded { // a renewal past its sign-in: the device signs in again
				return a, fmt.Errorf("the issuer refused: %w", orgpki.ErrSignInEnded)
			}
			if a.Refused != "" {
				return a, fmt.Errorf("the issuer refused: %s", a.Refused)
			}
			return a, nil
		}
	}
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// member is mb declaring a member's calls (mailboxclient.ShareMember):
// every pull here but the issuer's of the enrol drop box reads a
// broadcast (the root, the CRL, the answers), and whoever reads it, the
// issuer too, reads it as a member. The relay makes a shared mailbox a
// broadcast or a drop box at its first declared touch, for good
// (relay-server spec/Reach.tla KindOf): a holder's pull of a broadcast not
// made yet made it a drop box no member reads (the issuer's read-back of
// the root on a fresh relay, relay org v0.1.3 to v0.1.6:
// spec/orgmove/OrgHolds.tla RootReadable). A Mailbox that declares nothing
// (an undeclared mailboxclient.Client, a test's) is returned as it is.
func member(mb Mailbox) Mailbox {
	switch c := mb.(type) {
	case mailboxclient.Client:
		if c.Share != "" {
			c.Share = mailboxclient.ShareMember
		}
		return c
	case interface{ Declare(string) Mailbox }: // a test's relay that keeps kinds
		return c.Declare(mailboxclient.ShareMember)
	}
	return mb
}

// latest is the payload of broadcast mailbox's newest message, nil when it
// has none, read as a member.
func latest(ctx context.Context, mb Mailbox, mailbox string, wait time.Duration) ([]byte, error) {
	envs, _, err := member(mb).Pull(ctx, mailbox, 0, 0, wait)
	if err != nil || len(envs) == 0 {
		return nil, err
	}
	return envs[len(envs)-1].Payload, nil
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
// bound, not retryWait later (TestFollowPullsAgainAtOnceAfterAFailedPull). It returns when ctx ends.
func follow(ctx context.Context, mb Mailbox, mailbox string, every time.Duration, apply func([]byte) error, retry func() <-chan struct{}, logger *slog.Logger) {
	mb = member(mb) // a broadcast
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

var errNoMessage = errors.New("the relay holds none yet")
