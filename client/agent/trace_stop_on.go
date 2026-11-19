// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// The AgentStop trace (go test -tags relaytrace, RELAYTRACE=<dir>): a
// directServer's steps of relay spec/AgentStop.tla, one NDJSON line each,
// to <dir>/agentstop-<pid>-<n>.ndjson (one file per directServer, opened
// at its first line), checked by spec/TraceAgentStop.tla (spec/README.md
// "AgentStop traces"). Lines are written under one lock, each before the
// step others observe (an ABORT before aborted closes, a cut before cut
// closes, a session's end by whoever saw it first, the stopped flag read
// and set under the lock), so the file's order is an order the steps
// could take. The peers, the targets' bytes and the clock are not logged:
// TLC chooses them.
var stopTraces atomic.Uint64

type stopTracer struct {
	mu       sync.Mutex
	f        *os.File
	sessions int // ids given (register)
	calls    int // stop calls begun
}

type stopTraceSession struct {
	t    *stopTracer
	id   int
	once sync.Once // its end logged once (done)
}

// line writes m; t.mu held.
func (t *stopTracer) line(m map[string]any) {
	if t.f == nil {
		dir := os.Getenv("RELAYTRACE")
		if dir == "" {
			return
		}
		name := fmt.Sprintf("agentstop-%d-%d.ndjson", os.Getpid(), stopTraces.Add(1))
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
		if err != nil {
			panic(err)
		}
		t.f = f
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	if _, err := t.f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

func (t *stopTracer) log(m map[string]any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.line(m)
}

func (t *stopTracer) register(s *stopTraceSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions++
	s.t, s.id = t, t.sessions
	t.line(map[string]any{"ev": "Register", "s": s.id})
}

// begin numbers a stop call and reads whether it drains, under the lock.
func (t *stopTracer) begin(drain func() bool) (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.calls++
	d := drain()
	t.line(map[string]any{"ev": "StopBegin", "k": t.calls, "drain": d})
	return t.calls, d
}

func (t *stopTracer) drainEnd(k int, deadline bool, set func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	by := "over"
	if deadline {
		by = "deadline"
	}
	t.line(map[string]any{"ev": "DrainEnd", "k": k, "by": by})
	set()
}

func (t *stopTracer) reset(k int) { t.log(map[string]any{"ev": "StopReset", "k": k}) }
func (t *stopTracer) end(k int)   { t.log(map[string]any{"ev": "StopEnd", "k": k}) }

func (s *stopTraceSession) ev(ev string) {
	if s.t != nil {
		s.t.log(map[string]any{"ev": ev, "s": s.id})
	}
}

func (s *stopTraceSession) targetReset() { s.ev("TargetReset") }

// abort: an ended session's end first (its reset is then no ABORT).
func (s *stopTraceSession) abort(done <-chan struct{}) {
	select {
	case <-done:
		s.done()
	default:
	}
	s.ev("Abort")
}

func (s *stopTraceSession) done() { s.once.Do(func() { s.ev("Done") }) }
func (s *stopTraceSession) cut()  { s.ev("Cut") }
