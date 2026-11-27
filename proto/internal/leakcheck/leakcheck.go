// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package leakcheck fails a test binary whose tests leave goroutines running.
// Install it from a package's TestMain: os.Exit(leakcheck.Run(m)).
//
// Goroutines alive before m.Run are ignored (runtime, init, testing). After a
// passing run it polls for up to Wait for new ones to exit, then prints the
// stacks of the rest and returns 1. Stdlib only; the same file is kept in
// client/internal and proto/internal.
package leakcheck

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Wait is how long leaked goroutines get to exit after the last test.
var Wait = 3 * time.Second

var idRe = regexp.MustCompile(`^goroutine (\d+) `)

// benign are stack fragments of goroutines that belong to the runtime or the
// test harness rather than to the code under test.
var benign = []string{
	"leakcheck.",
	"testing.(*M)",
	"testing.tRunner",
	"os/signal.signal_recv",
	"os/signal.loop",
	"runtime.ensureSigM",
	"runtime/trace.",
	"runtime/pprof.",
	"runtime.goexit0",
}

func snapshot() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := map[string]string{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		if m := idRe.FindStringSubmatch(g); m != nil {
			out[m[1]] = g
		}
	}
	return out
}

func leaked(before map[string]string, ignore []string) []string {
	var out []string
next:
	for id, g := range snapshot() {
		if _, ok := before[id]; ok {
			continue
		}
		for _, b := range append(benign, ignore...) {
			if strings.Contains(g, b) {
				continue next
			}
		}
		out = append(out, g)
	}
	return out
}

// Run runs the package's tests and returns the exit code. ignore lists stack
// fragments of goroutines that are known to outlive the tests; each use must
// carry a comment naming the goroutine and the follow-up that removes it.
func Run(m *testing.M, ignore ...string) int { return RunFunc(m.Run, ignore...) }

// RunFunc is Run for a TestMain that wraps m.Run in other setup:
// os.Exit(leakcheck.RunFunc(func() int { return other.Run(m) })).
func RunFunc(run func() int, ignore ...string) int {
	before := snapshot()
	code := run()
	if linkDebugReports() > 0 && code == 0 {
		code = 1
	}
	if code != 0 {
		return code
	}
	var l []string
	for deadline := time.Now().Add(Wait); ; {
		if t, ok := http.DefaultTransport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
		if l = leaked(before, ignore); len(l) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(l) == 0 {
		return 0
	}
	fmt.Fprintf(os.Stderr, "leakcheck: %d goroutine(s) left after the tests:\n\n%s\n", len(l), strings.Join(l, "\n\n"))
	return 1
}
