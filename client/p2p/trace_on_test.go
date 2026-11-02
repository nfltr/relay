// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package p2p

import (
	"os"
	"path/filepath"
	"testing"
)

// traceTest records the test's SignalConns into $RELAYTRACE/<test>.ndjson.
func traceTest(t *testing.T) {
	if dir := os.Getenv("RELAYTRACE"); dir != "" {
		t.Cleanup(traceStart(filepath.Join(dir, t.Name()+".ndjson")))
	}
}
