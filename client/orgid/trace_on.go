// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build enroltrace

package orgid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Trace mode (go test -tags enroltrace, ENROLTRACE=<dir>) appends one JSON
// line per step to <dir>/<pid>.ndjson; nfltr's scripts/spec-enrol.sh
// traces checks it with spec/enrol/TraceEnrol.tla. A verifier writes under
// its lock, so its lines are in its order.
var traceMu sync.Mutex

func traceLine(l map[string]any) {
	dir := os.Getenv("ENROLTRACE")
	if dir == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}
