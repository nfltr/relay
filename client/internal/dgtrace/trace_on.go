// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package dgtrace

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// The DatagramAssoc trace (go test -tags relaytrace, RELAYTRACE=<dir>):
// one NDJSON line per step to <dir>/datagramassoc-<pid>.ndjson (spec/README.md
// "DatagramAssoc traces"). A traced process runs one association.
// Recording stops once both sides of the association ended (End).
var (
	mu   sync.Mutex
	file *os.File
	ends int
)

// On: RELAYTRACE names the trace's directory.
func On() bool { return os.Getenv("RELAYTRACE") != "" }

// Line writes one line.
func Line(line string) {
	if !On() {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	LineLocked(line)
}

// Lock holds the file across a step whose line is written once its
// outcome is known (LineLocked): a direct send, so its receiver's line,
// which waits for the lock, comes after it.
func Lock()   { mu.Lock() }
func Unlock() { mu.Unlock() }

// LineLocked is Line with the lock held.
func LineLocked(line string) {
	if ends >= 2 || !On() {
		return
	}
	if file == nil {
		f, err := os.OpenFile(filepath.Join(os.Getenv("RELAYTRACE"), "datagramassoc-"+strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
		if err != nil {
			panic(err)
		}
		file = f
	}
	if _, err := file.WriteString(line + "\n"); err != nil {
		panic(err)
	}
}

// End is one side's end; the recording stops at the second.
func End() {
	mu.Lock()
	ends++
	mu.Unlock()
}
