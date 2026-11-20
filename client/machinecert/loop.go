// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecert

import (
	"context"
	"errors"
	"math/rand/v2" // nosemgrep: math-random-used -- renewal jitter spreads machines' renewals; no secret
	"time"
)

// Loop renews a certificate for as long as its context lasts.
type Loop struct {
	// Renew asks a new certificate for cur (Client.Renew with the key).
	Renew func(ctx context.Context, cur *Cert) (*Cert, error)
	// Save keeps a new certificate (its file, the TLS config) before the
	// loop waits for the next renewal.
	Save func(*Cert) error
	// Now, Jitter (in [-1, 1]) and After are the clock, the spread and the
	// timer; nil: time.Now, uniform random, time.After.
	Now    func() time.Time
	Jitter func() float64
	After  func(time.Duration) <-chan time.Time
}

// Retry bounds: a failed renewal is retried after RetryMin, doubling up to
// RetryMax, for as long as it takes: also past the certificate's expiry
// (the relay renews it until its grace ends, relay-server
// spec/MachineAuth.tla BackAfterExpiry; mutant no-renew-after-expiry).
const (
	RetryMin = time.Minute
	RetryMax = 30 * time.Minute
)

// MaxSleep bounds one timer of the loop: it reads the clock again at least
// this often. Go's timers run on the monotonic clock, which stands still
// while the host sleeps (a laptop, a Docker Desktop VM on one), and a
// certificate's lifetime is wall clock: one timer for the whole wait woke
// as late as the host slept (guard TestRenewalLoopRenewsOnTimeAfterTheHostSlept).
const MaxSleep = time.Minute

// Run renews cur at RenewAt (a new jitter each time) and again for each
// certificate it gets, until ctx ends (nil) or the relay refuses for good
// (a final RefusedError: revoked, or expired past the relay's grace).
func (l Loop) Run(ctx context.Context, cur *Cert) error {
	now, jitter, after := l.Now, l.Jitter, l.After
	if now == nil {
		now = time.Now
	}
	if jitter == nil {
		jitter = func() float64 { return rand.Float64()*2 - 1 } // #nosec G404 -- spreads renewals; no secret
	}
	if after == nil {
		after = time.After
	}
	// wait until the wall-clock time until (Round(0): no monotonic
	// reading, so Sub is wall clock), MaxSleep at most per timer.
	wait := func(until time.Time) bool {
		until = until.Round(0)
		for {
			select {
			case <-ctx.Done():
				return false
			case <-after(min(max(until.Sub(now()), 0), MaxSleep)):
			}
			if !now().Before(until) {
				return true
			}
		}
	}
	for {
		if !wait(RenewAt(cur.Leaf.NotBefore, cur.Leaf.NotAfter, jitter())) {
			return nil
		}
		for backoff := RetryMin; ; backoff = min(2*backoff, RetryMax) {
			next, err := l.Renew(ctx, cur)
			if err == nil {
				if err = l.Save(next); err == nil {
					cur = next
					break
				}
			}
			var refused *RefusedError
			if errors.As(err, &refused) && refused.Final() {
				return err
			}
			if !wait(now().Add(backoff)) {
				return nil
			}
		}
	}
}
