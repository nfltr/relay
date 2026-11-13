// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package capaddr

import "testing"

// FuzzParse: Parse never panics, and an address it accepts is canonical and
// round-trips.
func FuzzParse(f *testing.F) {
	f.Add(Format(fixedAddress(f)))
	f.Add("nf1")
	f.Add("nf1aaaa")
	f.Add("home/db")
	f.Fuzz(func(t *testing.T, s string) {
		a, err := Parse(s)
		if err != nil {
			return
		}
		if Format(a) != s {
			t.Fatalf("accepted non-canonical %q (canonical %q)", s, Format(a))
		}
		if b, err := Parse(Format(a)); err != nil || b != a {
			t.Fatalf("round trip: %+v, %v", b, err)
		}
	})
}
