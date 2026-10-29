// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package handoff gives a value from a receive loop that serves many
// transactions (an agent's stream, a WireGuard exit's session, a broker
// fanout worker, an agent's A2A tunnel) to one transaction's consumer
// without letting that consumer hold the loop: the loop waits on a
// consumer only while it keeps taking, and never past a bound; then the
// caller refuses that one transaction with a typed error. It is the
// channel form of the TCP data path's stuck-client rule (a stuck
// receiver never holds the loop that serves every other session), for loops
// whose transactions have no per-transaction credit.
package handoff

import (
	"errors"
	"time"
)

// Stall is how long a shared receive loop waits for one consumer to take
// anything before the caller refuses that consumer's transaction. Each take
// ends the wait, so a slow consumer is paced and a stuck one is cut.
// ponytail: a consumer slower than its sender still paces the loop's other
// transactions; per-transaction credit (github.com/nfltr/link) removes the
// wait.
const Stall = 10 * time.Second

// ErrStalled reports a consumer that took nothing for the stall bound (or,
// with no bound, whose queue was full).
var ErrStalled = errors.New("consumer took nothing for the stall bound")

// ErrEnded reports a consumer that ended (done closed) before taking v.
var ErrEnded = errors.New("consumer ended")

// Send gives v to ch: at once while ch has room, else it waits for room
// until stall passes (ErrStalled) or done closes (ErrEnded). stall <= 0
// never waits: a full ch is ErrStalled (datagrams, which a full queue
// drops). The caller must be ch's only closer and never close it while
// sending.
func Send[T any](ch chan<- T, v T, done <-chan struct{}, stall time.Duration) error {
	select {
	case ch <- v:
		return nil
	default:
	}
	if stall <= 0 {
		return ErrStalled
	}
	t := time.NewTimer(stall)
	defer t.Stop()
	select {
	case ch <- v:
		return nil
	case <-done:
		return ErrEnded
	case <-t.C:
		return ErrStalled
	}
}
