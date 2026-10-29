// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agentwire

import "testing"

func TestParseGeneration(t *testing.T) {
	for _, tc := range []struct {
		vals []string
		want int
	}{
		{nil, 0},
		{[]string{""}, 0},
		{[]string{"x"}, 0},
		{[]string{"-3"}, 0},
		{[]string{"2"}, 2},
		{[]string{"7", "1"}, 7},
	} {
		if got := ParseGeneration(tc.vals); got != tc.want {
			t.Errorf("ParseGeneration(%q) = %d, want %d", tc.vals, got, tc.want)
		}
	}
	if p := GenerationPairs(); len(p) != 2 || p[0] != GenerationKey || ParseGeneration(p[1:]) != Generation {
		t.Fatalf("GenerationPairs() = %q", p)
	}
}
