// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package p2p

import (
	"encoding/json"
	"os"
	"sync"
)

// traceOn: with -tags relaytrace, a test that called traceStart records each
// SignalConn's steps, one NDJSON line each, checked against
// spec/SignalConn.tla by spec/TraceSignalConn.tla (scripts/spec.sh traces):
// a write (before its frame goes on the paths: the peer reads it after),
// a path joining (before its replay), a frame read from a path and a path's
// reader ending. SignalConns are numbered in the order they first record;
// paths by their id (the relay stream 0).
const traceOn = true

var (
	traceMu   sync.Mutex
	traceFile *os.File
	traceIDs  map[*SignalConn]int
)

// traceStart records into the file p until the returned stop.
func traceStart(p string) (stop func()) {
	f, err := os.Create(p)
	traceMu.Lock()
	defer traceMu.Unlock()
	if err != nil {
		return func() {}
	}
	traceFile, traceIDs = f, map[*SignalConn]int{}
	return func() {
		traceMu.Lock()
		defer traceMu.Unlock()
		_ = traceFile.Close()
		traceFile = nil
	}
}

func traceEmit(sc *SignalConn, ev map[string]any) {
	traceMu.Lock()
	defer traceMu.Unlock()
	if traceFile == nil {
		return
	}
	id, ok := traceIDs[sc]
	if !ok {
		id = len(traceIDs) + 1
		traceIDs[sc] = id
	}
	ev["sc"] = id
	b, _ := json.Marshal(ev)
	_, _ = traceFile.Write(append(b, '\n'))
}

func traceJoin(sc *SignalConn, path int) {
	traceEmit(sc, map[string]any{"op": "join", "path": path})
}

func traceWrite(sc *SignalConn, seq uint64, paths []pathEntry) {
	ids := make([]int, 0, len(paths))
	for _, p := range paths {
		ids = append(ids, p.id)
	}
	traceEmit(sc, map[string]any{"op": "write", "seq": seq, "paths": ids})
}

func traceRecv(sc *SignalConn, path int, seq uint64) {
	traceEmit(sc, map[string]any{"op": "recv", "path": path, "seq": seq})
}

func traceDrop(sc *SignalConn, path int) {
	traceEmit(sc, map[string]any{"op": "drop", "path": path})
}
