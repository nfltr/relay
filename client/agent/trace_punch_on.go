// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
)

// The DirectPunch trace (go test -tags relaytrace, RELAYTRACE=<dir>): the
// client's steps of relay spec/DirectPunch.tla for one punch
// (DirectEndpoint.punch), one NDJSON line each, to
// <dir>/directpunch-<pid>-<n>.ndjson, checked by spec/TraceDirectPunch.tla
// (spec/README.md "DirectPunch traces"). Every line is written by the
// punch's one goroutine, in the order it took the step. The agent's
// probes and the clock are not logged: TLC chooses them.
var punchTraces atomic.Uint64

type punchTrace struct{ f *os.File }

func tracePunch(offered, lan []string) punchTrace {
	dir := os.Getenv("RELAYTRACE")
	if dir == "" {
		return punchTrace{}
	}
	name := fmt.Sprintf("directpunch-%s-%d.ndjson", strconv.Itoa(os.Getpid()), punchTraces.Add(1))
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
	if err != nil {
		panic(err)
	}
	t := punchTrace{f}
	if lan == nil {
		lan = []string{}
	}
	t.line(map[string]any{"ev": "Init", "offered": offered, "lan": lan})
	return t
}

func (t punchTrace) line(m map[string]any) {
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

func (t punchTrace) learn(a string, lan, dialled bool) {
	out := "ignore"
	if dialled {
		out = "dial"
	}
	t.line(map[string]any{"ev": "Learn", "s": a, "tagged": true, "lan": lan, "out": out})
}
func (t punchTrace) up(a string, won bool) {
	t.line(map[string]any{"ev": "DialUp", "a": a})
	ev := "CloseLoser"
	if won {
		ev = "Win"
	}
	t.line(map[string]any{"ev": ev, "a": a})
}
func (t punchTrace) closeLoser(a string) { t.line(map[string]any{"ev": "CloseLoser", "a": a}) }
func (t punchTrace) settle()             { t.line(map[string]any{"ev": "Settle"}) }

// fail: a's dial ended without a connection. refused: it ended on its
// own, before its context did (the punch's bound, a win, the grace's
// end) and not by a timeout: the certificate check refused, or the
// network refused the send at once (sendmsg EADDRNOTAVAIL to a host
// bridge's .0 address, ICMP unreachable). DirectPunch.tla's Rogue: a dial
// that fails before the bound with no winner; any other failure must be
// the bound's or a win's (TraceDirectPunch.tla TraceRogue).
func (t punchTrace) fail(a string, ctxEnded bool, err error) {
	var ne net.Error
	timeout := errors.As(err, &ne) && ne.Timeout()
	t.line(map[string]any{"ev": "DialFail", "a": a, "refused": !ctxEnded && !timeout})
}
func (t punchTrace) end(won string) {
	if t.f == nil {
		return
	}
	t.line(map[string]any{"ev": "Return", "won": won})
	_ = t.f.Close()
}
