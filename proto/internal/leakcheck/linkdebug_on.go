// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build linkdebug

package leakcheck

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// Link's debug mode (-tags linkdebug, scripts/test-linkdebug.sh) prints its
// reports on stderr and fails nothing, and go test shows a passing
// package's stderr to nobody: a report only counted when another test of
// its package failed. Built with the tag, a test binary tees its stderr and
// fails (after a GC, so never-closed sessions are reported) on any
// "link debug:" line.
var linkDebug = tapStderr()

type stderrTap struct {
	orig, w *os.File
	done    chan struct{}
	reports atomic.Int32
}

func tapStderr() *stderrTap {
	r, w, err := os.Pipe()
	if err != nil {
		return nil
	}
	t := &stderrTap{orig: os.Stderr, w: w, done: make(chan struct{})}
	os.Stderr = w
	go func() {
		defer close(t.done)
		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if strings.Contains(line, "link debug:") {
				t.reports.Add(1)
			}
			_, _ = io.WriteString(t.orig, line)
			if err != nil {
				return
			}
		}
	}()
	return t
}

// linkDebugReports collects the reports of sessions garbage-collected
// unclosed, restores stderr and returns how many reports the run printed.
func linkDebugReports() int {
	if linkDebug == nil {
		return 0
	}
	for range 2 { // a cleanup runs after the GC that found its session
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
	os.Stderr = linkDebug.orig
	_ = linkDebug.w.Close()
	<-linkDebug.done
	n := int(linkDebug.reports.Load())
	if n > 0 {
		fmt.Fprintf(os.Stderr, "leakcheck: %d link debug report(s) above\n", n)
	}
	return n
}
