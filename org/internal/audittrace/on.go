// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build enroltrace

// Package audittrace records the issuer's steps of spec/MoveAudit.tla
// (relay spec/README.md "AuditLog and MoveAudit traces"): each a JSON
// line of <AUDITTRACE>/<pid>.moveaudit, beside the machine's "write"
// lines (relay client/orgaudit, -tags audittrace).
package audittrace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

var mu sync.Mutex

// Line records one step.
func Line(m map[string]any) {
	out := os.Getenv("AUDITTRACE")
	if out == "" {
		return
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(filepath.Join(out, strconv.Itoa(os.Getpid())+".moveaudit"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- the tester's AUDITTRACE
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}
