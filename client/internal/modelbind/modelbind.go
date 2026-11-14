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
	"cap.register": "cap_address.pv registration: design (nfltr docs/decisions/nf1-risks-2026-11-14.md, lane NF1REG adds the row with the codec's registration proof)",
	"dgram.tag":    "cap_address.pv and e2ee_tcp.pv datagrams: design (nfltr docs/decisions/nf1-udp-2026-11-14.md, lane UDP3 adds the row with the direct datagram code)",
	"cap.kind":     "cap_address.pv the kind (u1): design (nfltr docs/decisions/nf1-udp-2026-11-14.md, lane UDP2 adds the row with the hints' kind)",
	"org.kind":     "e2ee_tcp.pv the kind (ALPN nfltr-dg/): design (nfltr docs/decisions/nf1-udp-2026-11-14.md, lane UDP2 adds the row with the kind in service_alpn.go)",
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
