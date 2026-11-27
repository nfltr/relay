// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"strings"
	"testing"
)

// FuzzParseTarget: ParseTarget matches nfltr's parse (checkParity, its
// one refusal aside), never panics, reads back its String, and never
// echoes what may be an address's text.
func FuzzParseTarget(f *testing.F) {
	addr := mintAddress(f, "relay.test:8443")
	for _, s := range []string{
		"home/db", "web-1.db/pg", "pg@db", "m7f3a91c2-db/pg", "a.b.c/db", "home/../db", "pg@db/x",
		addr, typo(addr), addr + "/db", "x." + addr + "/db", "db@" + addr, addr[:len(addr)-5] + "/db",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		checkParity(t, s)
		got, err := ParseTarget(s)
		out := got.String()
		if err != nil {
			out = err.Error()
		}
		for _, tok := range tokens(s) {
			if looksLikeAddress(tok) && got.Kind != AddressTarget && strings.Contains(out, tok) {
				t.Fatalf("ParseTarget(%q) echoes %q: %q", s, tok, out)
			}
		}
	})
}
