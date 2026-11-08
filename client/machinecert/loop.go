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
// RetryMax, never past the certificate's expiry.
const (
	RetryMin = time.Minute
	RetryMax = 30 * time.Minute
)

// Run renews cur at RenewAt (a new jitter each time) and again for each
// certificate it gets, until ctx ends (nil) or the relay refuses for good
// (a final RefusedError: enrol again) or the certificate expired unrenewed.
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
	wait := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-after(max(d, 0)):
			return true
		}
	}
	for {
		if !wait(RenewAt(cur.Leaf.NotBefore, cur.Leaf.NotAfter, jitter()).Sub(now())) {
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
			left := cur.Leaf.NotAfter.Sub(now())
			if left <= 0 {
				return errors.Join(errors.New("machinecert: the certificate expired unrenewed"), err)
			}
			if !wait(min(backoff, left)) {
				return nil
			}
		}
	}
}
