// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"math/rand"
	"time"
)

const (
	// DefaultReconnectBase is the initial wait after the first reconnect failure.
	DefaultReconnectBase = time.Second
	// DefaultReconnectMax caps exponential growth between reconnect attempts.
	DefaultReconnectMax = 30 * time.Second
)

// ReconnectBackoff tracks consecutive reconnect failures and returns jittered
// exponential delays (base 1s, factor 2×, cap 30s, jitter 0–25%).
type ReconnectBackoff struct {
	failures   int
	base       time.Duration
	max        time.Duration
	randInt63n func(int64) int64
}

// ReconnectBackoffOption configures NewReconnectBackoff.
type ReconnectBackoffOption func(*ReconnectBackoff)

// WithReconnectMax sets the delay cap (default DefaultReconnectMax).
func WithReconnectMax(d time.Duration) ReconnectBackoffOption {
	return func(b *ReconnectBackoff) {
		if d > 0 {
			b.max = d
		}
	}
}

// NewReconnectBackoff builds a backoff tracker for gRPC reconnect loops.
func NewReconnectBackoff(base time.Duration, opts ...ReconnectBackoffOption) *ReconnectBackoff {
	if base <= 0 {
		base = DefaultReconnectBase
	}
	b := &ReconnectBackoff{
		base:       base,
		max:        DefaultReconnectMax,
		randInt63n: rand.Int63n,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Reset clears consecutive failure state after a successful reconnect.
func (b *ReconnectBackoff) Reset() {
	b.failures = 0
}

// DelayAfterFailure records a failure and returns how long to wait before the
// next reconnect attempt, including 0–25% jitter on the capped exponential delay.
func (b *ReconnectBackoff) DelayAfterFailure() time.Duration {
	b.failures++
	return b.delayForFailures(b.failures)
}

func (b *ReconnectBackoff) delayForFailures(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := b.base
	for i := 1; i < n; i++ {
		if d >= b.max {
			d = b.max
			break
		}
		next := d * 2
		if next > b.max {
			d = b.max
			break
		}
		d = next
	}
	if d > b.max {
		d = b.max
	}
	return d + reconnectJitter(d, b.randInt63n)
}

// reconnectJitter returns a uniform random duration in [0, 25% of base).
func reconnectJitter(base time.Duration, randInt63n func(int64) int64) time.Duration {
	if base <= 0 {
		return 0
	}
	span := int64(base / 4)
	if span <= 0 {
		return 0
	}
	return time.Duration(randInt63n(span))
}
