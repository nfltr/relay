// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build audittrace

package orgaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Trace mode (go test -tags audittrace, AUDITTRACE=<dir>) appends the
// steps of spec/AuditLog.tla a machine directory's log takes to
// <dir>/auditlog-<hash of the directory>.ndjson, each under the log's
// lock (so the file's order is the log's, across processes too);
// spec/TraceAuditLog.tla checks each file. p names the process (its
// owner id; a Log with none, a keeper that served nothing, by its
// address), s the session, q a recovered owner, seq the line's.
//
//	intent     the owner file lists s (Intent)
//	open       s's open line (OpenLine)
//	close      s's close line (CloseLine)
//	forget     the owner file forgets s (Forget)
//	lost       p wrote q's session s's lost close (Recover)
//	recovered  p deleted q's owner file (RecoverDone)
//	crash      p's owner lock released (a test's kill: Crash)
//	ship       the issuer acknowledged up to seq (Rotate's acked: Ship)
//	rotate     the file now starts at seq (Rotate)
//
// Each line written is also {"ev":"write","n":seq} in <dir>/<pid>.moveaudit,
// the machine's half of spec/MoveAudit.tla's trace (relay org's
// audittrace files log the issuer's).
var traceMu sync.Mutex

func (l *Log) trace(ev, s, q string, seq uint64) {
	l.mu.Lock()
	p := l.traceName()
	l.mu.Unlock()
	l.traceAs(p, ev, s, q, seq)
}

// traceHeld is trace with l.mu held.
func (l *Log) traceHeld(ev, s string) { l.traceAs(l.traceName(), ev, s, "", 0) }

func (l *Log) traceAs(p, ev, s, q string, seq uint64) {
	m := map[string]any{"ev": ev, "p": p}
	if s != "" {
		m["s"] = s
	}
	if q != "" {
		m["q"] = q
	}
	if ev == "open" || ev == "close" || ev == "lost" {
		m["seq"] = seq
	}
	traceTo(dirTrace(l.Dir), m)
}

func (l *Log) traceName() string {
	if l.id != "" {
		return l.id
	}
	return fmt.Sprintf("k%p", l)
}

func (l *Log) traceCrash(unlock func()) func() {
	return func() {
		l.trace("crash", "", "", 0)
		unlock()
	}
}

func traceWrite(seq uint64) {
	traceTo(strconv.Itoa(os.Getpid())+".moveaudit", map[string]any{"ev": "write", "n": seq})
}

// traceShip logs the seq of the line that ends at acked (0: none).
func traceShip(dir string, f *os.File, acked int64) {
	var seq uint64
	if fi, err := f.Stat(); err == nil {
		acked = min(acked, fi.Size()) // past the end: every line (Rotate's min)
	}
	if acked > 0 {
		buf := make([]byte, acked)
		if _, err := f.ReadAt(buf, 0); err == nil {
			buf = bytes.TrimSuffix(buf, []byte("\n"))
			if r, err := Parse(buf[bytes.LastIndexByte(buf, '\n')+1:]); err == nil {
				seq = r.Seq
			}
		}
	}
	traceTo(dirTrace(dir), map[string]any{"ev": "ship", "seq": seq})
}

func traceRotate(dir string, kept []byte) {
	first, _, _ := bytes.Cut(kept, []byte("\n"))
	r, _ := Parse(first)
	traceTo(dirTrace(dir), map[string]any{"ev": "rotate", "seq": r.Seq})
}

func dirTrace(dir string) string {
	abs, _ := filepath.Abs(dir)
	sum := sha256.Sum256([]byte(abs))
	return "auditlog-" + hex.EncodeToString(sum[:8]) + ".ndjson"
}

func traceTo(name string, m map[string]any) {
	out := os.Getenv("AUDITTRACE")
	if out == "" {
		return
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(out, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- the tester's AUDITTRACE
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}
