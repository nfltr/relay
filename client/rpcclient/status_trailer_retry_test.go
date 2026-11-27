// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"testing"
	"time"
)

// zeroBackoff makes the retry loop spin without real waits so the tests stay
// fast and deterministic.
func zeroBackoff(int) time.Duration { return 0 }

// The terminal status must survive a brief stream flap: a send that fails the
// first two attempts then succeeds is delivered, not dropped. This is the
// direct regression for "rpcclient: failed to send a2a-status trailer" losing
// a completed task (the 0/N-completed lost-session-binding).
func TestSendStatusTrailerWithRetry_SucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	send := func() error {
		calls++
		if calls < 3 {
			return errors.New("stream reconnecting")
		}
		return nil
	}
	if err := sendStatusTrailerWithRetry(context.Background(), send, 6, zeroBackoff); err != nil {
		t.Fatalf("expected eventual delivery; got err=%v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 send attempts (2 failures + 1 success); got %d", calls)
	}
}

// First-try success sends exactly once (no needless retries on the happy path).
func TestSendStatusTrailerWithRetry_FirstTrySendsOnce(t *testing.T) {
	calls := 0
	send := func() error { calls++; return nil }
	if err := sendStatusTrailerWithRetry(context.Background(), send, 6, zeroBackoff); err != nil {
		t.Fatalf("unexpected err=%v", err)
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 send; got %d", calls)
	}
}

// When every attempt fails, the loop exhausts exactly `attempts` tries and
// returns the last error (handler then logs + falls to rehydrate-on-reconnect).
func TestSendStatusTrailerWithRetry_ExhaustsAttemptsAndReturnsLastError(t *testing.T) {
	calls := 0
	sentinel := errors.New("stream gone")
	send := func() error { calls++; return sentinel }
	err := sendStatusTrailerWithRetry(context.Background(), send, 4, zeroBackoff)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected last send error; got %v", err)
	}
	if calls != 4 {
		t.Errorf("expected 4 attempts; got %d", calls)
	}
}

// A cancelled context (agent shutting down) stops retrying immediately rather
// than blocking through the remaining backoffs.
func TestSendStatusTrailerWithRetry_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	send := func() error { calls++; return errors.New("stream gone") }
	err := sendStatusTrailerWithRetry(ctx, send, 6, zeroBackoff)
	if err == nil {
		t.Fatal("expected error when ctx is cancelled")
	}
	if calls != 1 {
		t.Errorf("expected to stop after the first failed attempt once ctx is done; got %d", calls)
	}
}

// statusTrailerBackoff grows then caps at 3s so the retry budget can ride a
// reconnect without unbounded blocking.
func TestStatusTrailerBackoffGrowsAndCaps(t *testing.T) {
	if got := statusTrailerBackoff(1); got != 250*time.Millisecond {
		t.Errorf("attempt 1 backoff = %v, want 250ms", got)
	}
	if got := statusTrailerBackoff(3); got != time.Second {
		t.Errorf("attempt 3 backoff = %v, want 1s", got)
	}
	if got := statusTrailerBackoff(10); got != 3*time.Second {
		t.Errorf("attempt 10 backoff = %v, want 3s (capped)", got)
	}
}
