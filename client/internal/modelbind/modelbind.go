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
	// spec/proverif/orggroup.pv (a design, lane ONEGROUP): the rows come
	// with its code, lane ONEGROUP-C1 (org/orgpki TestOrgGroupModelBindings).
	"group.movesig": "ONEGROUP-C1: org/orgpki move order",
	"group.ou":      "ONEGROUP-C1: client/orgid groups from the certificate",
	"group.pin":     "ONEGROUP-C2: relay-server org_status root pin",
	// spec/proverif/svc_access.pv (a design, lane SERVICEACCESS): the rows
	// come with its code lanes (nfltr docs/decisions/service-access-2026-11-25.md):
	// svc.hdrwho and svc.aud since lane SA2, svc.rulesig and svc.apprpol
	// since lane SA3, the grant ids since lane SA4.
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
