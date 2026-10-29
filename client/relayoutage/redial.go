// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relayoutage

import (
	"math/rand/v2"
	"time"
)

const (
	// RedialBase is the first redial delay after a relay connection fails.
	RedialBase = 250 * time.Millisecond
	// RedialFlat is how many redials of an outage wait RedialBase before
	// the delay starts doubling: a restarting relay (process or container)
	// is usually back within their 2-3 s, and a doubled delay left a
	// client up to 1.5 s behind a relay that was already up.
	RedialFlat = 8
	// FastRedialMax caps redial delays for the first FastRedialWindow of an
	// outage: a relay restart or deploy is usually over by then, and a
	// client redials within a second of the relay's return.
	FastRedialMax = time.Second
	// FastRedialWindow is how long an outage keeps the fast cap.
	FastRedialWindow = time.Minute
)

// RedialDelay is the delay before redial n (1-based) of an outage that
// began at since: RedialBase for the first RedialFlat redials, then doubling
// per redial, capped at FastRedialMax during the first FastRedialWindow and
// at ceiling (the caller's longest wait, e.g. --retry-wait) after it, plus
// 0-50% jitter so a fleet does not redial in lockstep. A ceiling <= 0 keeps
// every delay at RedialBase.
func RedialDelay(n int, since time.Time, ceiling time.Duration) time.Duration {
	if time.Since(since) < FastRedialWindow {
		ceiling = min(ceiling, FastRedialMax)
	}
	d := RedialBase
	for i := RedialFlat; i < n && d < ceiling; i++ {
		d *= 2
	}
	if ceiling > 0 {
		d = min(d, ceiling)
	}
	if half := int64(d / 2); half > 0 {
		d += time.Duration(rand.Int64N(half + 1))
	}
	return d
}
