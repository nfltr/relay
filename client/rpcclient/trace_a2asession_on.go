// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package rpcclient

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// The A2ASession trace (go test -tags relaytrace, RELAYTRACE=<dir>): the
// session steps of relay spec/A2ASession.tla of every agent in the
// process, one NDJSON line each, to <dir>/a2asession-<pid>.ndjson, checked
// per caller and callee by relay spec/TraceA2ASession.tla (spec/README.md
// "A2ASession traces"). A line names its step (ev), the pair (f: the
// caller's ref, t: the callee's), the call (k: its txn), the session (s:
// its number in the pair, 1, 2, ... in the order the trace first names it)
// and the call number (c); a Retry also names the resume it retries (os,
// oc). Each line is written before its step can be seen by the other end
// (the callee's before its answer goes out, the caller's Resume under the
// sessions' lock before its resume goes out), under asMu, so the file's
// order is one the run took. The relay's steps are not logged.
var (
	asMu   sync.Mutex
	asFile *os.File
	asSids = map[string]map[[a2aSessionIDLen]byte]int{} // under asMu: per pair, a session's number
)

// asSid is session id's number in pair p (under asMu).
func asSid(p string, id []byte) int {
	if len(id) < a2aSessionIDLen {
		return 0
	}
	m := asSids[p]
	if m == nil {
		m = map[[a2aSessionIDLen]byte]int{}
		asSids[p] = m
	}
	k := [a2aSessionIDLen]byte(id)
	if m[k] == 0 {
		m[k] = len(m) + 1
	}
	return m[k]
}

// traceAS logs step ev of the pair caller to callee: call txn, session
// sid, call number c, and for a Retry the retry message it answered.
func traceAS(ev, caller, callee, txn string, sid []byte, c uint64, retry []byte) {
	if os.Getenv("RELAYTRACE") == "" {
		return
	}
	asMu.Lock()
	defer asMu.Unlock()
	p := caller + ">" + callee
	s, os1, oc := 0, 0, uint64(0)
	if sid != nil {
		s = asSid(p, sid)
	}
	if len(retry) == a2aRetryLen {
		os1, oc = asSid(p, retry[:a2aSessionIDLen]), binary.BigEndian.Uint64(retry[a2aSessionIDLen:])
	}
	if asFile == nil {
		f, err := os.OpenFile(filepath.Join(os.Getenv("RELAYTRACE"), "a2asession-"+strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
		if err != nil {
			panic(err)
		}
		asFile = f
	}
	if _, err := asFile.Write(fmt.Appendf(nil, `{"ev":%q,"f":%q,"t":%q,"k":%q,"s":%d,"c":%d,"os":%d,"oc":%d}`+"\n", ev, caller, callee, txn, s, c, os1, oc)); err != nil {
		panic(err)
	}
}
