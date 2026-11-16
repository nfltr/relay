// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package modelbind holds what every bindings test of the spec/proverif
// models shares (spec/proverif/README.md "Bindings"): the BIND ids whose
// rows wait for their code, and the check of a model's ids against a
// test's rows.
package modelbind

import (
	"fmt"
	"regexp"
	"slices"
)

// Pending lists the BIND ids a model declares whose row is not in this
// module yet: id -> where the row comes from. Every bindings test and
// client's TestEveryModelBindingHasARow exempt these ids, and each fails
// once a pending id has a row, so the list cannot go stale.
var Pending = map[string]string{
	// spec/proverif/browser_peer.pv: a design (nfltr
	// docs/decisions/browser-peer-2026-11-16.md); the browser bundle's lane
	// adds the rows.
	"browser.bundle": "the browser bundle's lane (BP2): its hash check",
	"browser.dc.nf1": "the browser bundle's lane (BP2): a data channel's own nf1 handshake",
	"browser.signal": "the agent's browser-peer lane (BP3): SDP only after Admit",
}

// Check compares the BIND ids model (a model's source) declares that id
// matches (its first group), less the pending ones, with a test's rows. A
// row for a pending id is an error too: drop the id from Pending.
func Check(model []byte, id *regexp.Regexp, rows []string) error {
	return check(model, id, rows, Pending)
}

func check(model []byte, id *regexp.Regexp, rows []string, pending map[string]string) error {
	var ids []string
	for _, m := range id.FindAllSubmatch(model, -1) {
		if b := string(m[1]); pending[b] == "" && !slices.Contains(ids, b) {
			ids = append(ids, b)
		}
	}
	for _, r := range rows {
		if _, ok := pending[r]; ok {
			return fmt.Errorf("BIND:%s has a row: drop it from modelbind.Pending", r)
		}
	}
	rows = slices.Sorted(slices.Values(rows))
	slices.Sort(ids)
	if !slices.Equal(ids, rows) {
		return fmt.Errorf("BIND ids %v, rows %v: each binding of the model needs one row (or an entry in modelbind.Pending)", ids, rows)
	}
	return nil
}
