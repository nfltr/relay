// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build pairtrace

package pairfile

import (
	"encoding/json"
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Trace mode (go test -tags pairtrace, PAIRTRACE=<dir>) appends one JSON
// line per step to <dir>/<pid>-<hash of the key's path>.ndjson, with the files as the step
// left them; scripts/spec-pair.sh traces checks each file with
// spec/pair/TraceMachinePair.tla.
var traceMu sync.Mutex

func trace(p Pair, ev, from string) {
	dir := os.Getenv("PAIRTRACE")
	if dir == "" {
		return
	}
	cert, cerr := os.ReadFile(p.Cert)
	key, kerr := os.ReadFile(p.Key)
	next, nerr := os.ReadFile(p.Next())
	l := map[string]any{
		"ev": ev,
		"ce": cerr == nil,
		"ck": kerr == nil && p.Match(cert, key) == nil,
		"cn": nerr == nil && p.Match(cert, next) == nil,
		"nx": nerr == nil,
	}
	if ev == "read" {
		l["from"] = from
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(p.Key))
	name := strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(h.Sum64(), 16) + ".ndjson"
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}
