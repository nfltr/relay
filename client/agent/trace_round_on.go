// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// The PunchRound trace (go test -tags relaytrace, RELAYTRACE=<dir>): the
// client's steps of relay spec/PunchRound.tla for one round
// (DirectSession.punchRound), one NDJSON line each, to
// <dir>/punchround-<pid>-<n>.ndjson, checked by spec/TracePunchRound.tla
// (spec/README.md "PunchRound traces"). The round's one goroutine writes
// every line in the order it took the step. The delays, the clock, the
// losses and the agent's vanishing are not logged: TLC chooses them.
type roundTrace struct{ f *os.File }

func traceRound() roundTrace {
	dir := os.Getenv("RELAYTRACE")
	if dir == "" {
		return roundTrace{}
	}
	name := fmt.Sprintf("punchround-%s-%d.ndjson", strconv.Itoa(os.Getpid()), punchTraces.Add(1))
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
	if err != nil {
		panic(err)
	}
	return roundTrace{f}
}

func (t roundTrace) line(m map[string]any) {
	if t.f == nil {
		return
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	if _, err := t.f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

func (t roundTrace) start(n int) { t.line(map[string]any{"ev": "Start", "att": n}) }
func (t roundTrace) sync(rtt time.Duration) {
	t.line(map[string]any{"ev": "Sync", "rtt_us": rtt.Microseconds()})
}
func (t roundTrace) dial(rtt, wait, since time.Duration) {
	t.line(map[string]any{"ev": "Dial", "rtt_us": rtt.Microseconds(), "wait_us": wait.Microseconds(), "since_us": since.Microseconds()})
}

// result is the attempt's end: Win, NoAnswer, Refused, or Withheld for
// every end before a dial (no offer, the offer's refusal, no candidates).
func (t roundTrace) result(reason string) {
	ev := "Withheld"
	switch reason {
	case "":
		ev = "Win"
	case ReasonNoAnswer:
		ev = "NoAnswer"
	case ReasonRefusedCert:
		ev = "Refused"
	}
	t.line(map[string]any{"ev": ev, "reason": reason})
}

func (t roundTrace) end() {
	if t.f != nil {
		_ = t.f.Close()
	}
}
