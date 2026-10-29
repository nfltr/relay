// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relayoutage

import (
	"testing"
	"time"
)

func TestRedialDelay(t *testing.T) {
	now, old := time.Now(), time.Now().Add(-2*FastRedialWindow)
	for range 200 {
		for _, tc := range []struct {
			n       int
			since   time.Time
			ceiling time.Duration
			want    time.Duration // before jitter (0-50%)
		}{
			{1, now, 5 * time.Second, RedialBase},
			{RedialFlat, now, 5 * time.Second, RedialBase}, // a restarting relay is back within the flat redials
			{RedialFlat + 1, now, 5 * time.Second, 2 * RedialBase},
			{RedialFlat + 6, now, 5 * time.Second, FastRedialMax},   // a fresh outage stays fast
			{RedialFlat + 6, old, 5 * time.Second, 5 * time.Second}, // a long one backs off to the ceiling
			{RedialFlat + 1, old, 5 * time.Second, 2 * RedialBase},
			{3, now, 100 * time.Millisecond, 100 * time.Millisecond},
			{9, old, 0, RedialBase},
		} {
			if d := RedialDelay(tc.n, tc.since, tc.ceiling); d < tc.want || d > tc.want*3/2 {
				t.Fatalf("RedialDelay(%d, -%v, %v) = %v, want in [%v, %v]", tc.n, time.Since(tc.since).Round(time.Second), tc.ceiling, d, tc.want, tc.want*3/2)
			}
		}
	}
}
