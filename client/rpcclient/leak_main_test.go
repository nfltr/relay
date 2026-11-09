// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"os"
	"testing"

	"github.com/nfltr/relay/client/internal/leakcheck"
)

// replayBase holds the A2A E2EE replay records of the tests' agents
// (keyedAgent): one directory each, kept across a restartSessions.
var replayBase string

// TestMain fails the package when its tests leave goroutines running.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rpcclient-replay-")
	if err != nil {
		panic(err)
	}
	replayBase = dir
	code := leakcheck.Run(m)
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
