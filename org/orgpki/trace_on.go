// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build enroltrace

package orgpki

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Trace mode (go test -tags enroltrace, ENROLTRACE=<dir>) appends one JSON
// line per step to <dir>/<pid>.ndjson; scripts/spec-enrol.sh traces checks
// it with spec/enrol/TraceEnrol.tla. The issuer writes under its lock and a
// verifier under its own, so each one's lines are in its order.
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

// Move traces (ORGMOVETRACE=<dir>, scripts/spec-orgmove.sh traces): every
// commit of an issuer, by its line's hash and the hash before it, and a
// move's send; spec/orgmove/TraceOrgMove.tla checks them.
var moveMu sync.Mutex

func traceCommit(orgID string, e Entry, prev, head string) {
	ev := "act"
	switch e.Act {
	case ActMoved:
		ev = "fence"
	case ActArrived:
		return // TraceImport, once the import's log is written
	}
	moveTrace(map[string]any{"ev": ev, "o": orgID, "act": e.Act, "k": e.Key, "num": e.Number, "p": prev, "h": head})
}

func moveTrace(l map[string]any) {
	dir := os.Getenv("ORGMOVETRACE")
	if dir == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	moveMu.Lock()
	defer moveMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}
