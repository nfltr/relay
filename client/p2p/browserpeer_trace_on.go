// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package p2p

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
)

// The BrowserPeer trace (go test -tags relaytrace, RELAYTRACE=<dir>): the
// agent's steps of relay spec/BrowserPeer.tla for one control session,
// one NDJSON line each, to <dir>/browserpeer-<pid>-<n>.ndjson (n numbers
// the process's control sessions), checked by spec/TraceBrowserPeer.tla
// (spec/README.md "BrowserPeer traces"). Each line is written under the
// session's lock, in the step's critical section. A line names the step
// (ev) and, for a stream's, its number (s, from 1); the first line, Serve,
// the session's data channel cap (maxdc).
type bpTrace struct{ f *os.File }

var bpTraces atomic.Int64

func newBPTrace(maxDC int) *bpTrace {
	dir := os.Getenv("RELAYTRACE")
	if dir == "" {
		return nil
	}
	n := bpTraces.Add(1)
	f, err := os.OpenFile(filepath.Join(dir, "browserpeer-"+strconv.Itoa(os.Getpid())+"-"+strconv.FormatInt(n, 10)+".ndjson"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- the tester's RELAYTRACE
	if err != nil {
		panic(err)
	}
	t := &bpTrace{f: f}
	t.line(fmt.Sprintf(`{"ev":"Serve","maxdc":%d}`, maxDC))
	return t
}

func (t *bpTrace) line(l string) {
	if _, err := t.f.WriteString(l + "\n"); err != nil {
		panic(err)
	}
}

// emit records step ev (CtlOpen, CtlAdmit, CtlEnd, Offer, PCUp, PCFail,
// Reap, OpenDC, Deliver, Complete, Break, Refuse); s is a stream's number,
// 0 for the session's own steps.
func (t *bpTrace) emit(ev string, s int) {
	if t == nil {
		return
	}
	if s == 0 {
		t.line(fmt.Sprintf(`{"ev":%q}`, ev))
		return
	}
	t.line(fmt.Sprintf(`{"ev":%q,"s":%d}`, ev, s))
}

func (t *bpTrace) close() {
	if t != nil {
		_ = t.f.Close()
	}
}
