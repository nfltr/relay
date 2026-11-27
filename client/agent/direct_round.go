// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"time"
)

// punchAttempts is the most attempts one round makes toward a pair: a
// retry, with its own exchange and round trip, only after no candidate
// answered (relay spec/PunchRound.tla RetryBound, RetryOnlyNoAnswer).
const punchAttempts = 3

// punchAttempt is one attempt's account, for tests (DirectClient.attempted).
type punchAttempt struct {
	n         int           // 1..punchAttempts
	rtt, wait time.Duration // the exchange's round trip, the wait after the sync
	sinceSync time.Duration // the sync to the dial
	reason    string        // "" won, else why not
}

// punchRound punches p up to punchAttempts times; p.mu held. It returns
// the last attempt's reason ("" when one won) and how many it made. The
// session runs relayed meanwhile (the round never holds it: NeverHeld),
// and a session that ended starts no further attempt (its loop reports
// nothing for it: TestDirectPunchRoundStopsWhenTheSessionEnds).
func (s *DirectSession) punchRound(p *directPair) (reason string, n int) {
	tr := traceRound()
	defer tr.end()
	for n = 1; ; n++ {
		tr.start(n)
		reason = s.punch(p, n, tr)
		if reason == "" {
			s.d.count("ok")
		} else {
			s.d.count(reason)
		}
		if reason != ReasonNoAnswer || n == punchAttempts || s.ended() {
			return reason, n
		}
	}
}

// syncWait waits, after the client's sync and before it dials, half the
// exchange's round trip, so the agent's first probe (sent on reading the
// sync) has left its NAT when the first Initial reaches it
// (spec/PunchRound.tla InitialAfterProbe), or until ctx ends (the dial
// then fails at once: no answer).
func syncWait(ctx context.Context, rtt time.Duration) time.Duration {
	wait := rtt / 2
	select {
	case <-time.After(wait):
	case <-ctx.Done():
	}
	return wait
}

// ended reports whether the session is over: closed or reset here (a
// client's clean end closes Done only a detach bound after Close), or
// ended.
func (s *DirectSession) ended() bool {
	if s.nc.closed.Load() {
		return true
	}
	select {
	case <-s.c.Done():
		return true
	default:
		return false
	}
}
