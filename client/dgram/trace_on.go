// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package dgram

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// The DatagramAssoc trace (go test -tags relaytrace, RELAYTRACE=<dir>):
// the steps of relay spec/DatagramAssoc.tla both sides of an association
// take, one NDJSON line each, to <dir>/datagramassoc-<pid>.ndjson, checked
// by spec/TraceDatagramAssoc.tla (spec/README.md "DatagramAssoc traces").
// A traced process runs one association. Each line is written in the
// critical section of its step (the side's lock), so a frame's line comes
// before its receiver's, and the lines of one side's frames are in its
// stream order. Recording stops at the association's end (its cut is not
// traced). A line names the step (ev), the flow id (f), a source (s, with
// whether it is admitted: adm), a frame's kind (k) and what the side did
// with it (out).
var (
	trMu    sync.Mutex
	trFile  *os.File
	trEnded bool
)

func trace(line string) {
	dir := os.Getenv("RELAYTRACE")
	if dir == "" {
		return
	}
	trMu.Lock()
	defer trMu.Unlock()
	if trEnded {
		return
	}
	if trFile == nil {
		f, err := os.OpenFile(filepath.Join(dir, "datagramassoc-"+strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
		if err != nil {
			panic(err)
		}
		trFile = f
	}
	if _, err := trFile.WriteString(line + "\n"); err != nil {
		panic(err)
	}
}

func traceOpen(maxFlows int) { trace(fmt.Sprintf(`{"ev":"AssocOpen","n":%d}`, maxFlows)) }
func traceRead(src string, f uint64, op string) {
	trace(fmt.Sprintf(`{"ev":"Read","s":%q,"adm":true,"f":%d,"op":%q}`, src, f, op))
}
func traceReadDrop(src string, adm bool) {
	trace(fmt.Sprintf(`{"ev":"Read","s":%q,"adm":%v,"f":0,"op":"drop"}`, src, adm))
}
func traceRecvC(k string, f uint64, out string) {
	trace(fmt.Sprintf(`{"ev":"RecvC","k":%q,"f":%d,"out":%q}`, k, f, out))
}
func traceExpireC(f uint64) { trace(fmt.Sprintf(`{"ev":"ExpireC","f":%d}`, f)) }
func traceRecvA(k string, f uint64, out string) {
	trace(fmt.Sprintf(`{"ev":"RecvA","k":%q,"f":%d,"out":%q}`, k, f, out))
}
func traceReplyA(f uint64)  { trace(fmt.Sprintf(`{"ev":"ReplyA","f":%d}`, f)) }
func traceExpireA(f uint64) { trace(fmt.Sprintf(`{"ev":"ExpireA","f":%d}`, f)) }
func traceEnd() {
	trMu.Lock()
	trEnded = true
	trMu.Unlock()
}
