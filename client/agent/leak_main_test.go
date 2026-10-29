// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"testing"

	"github.com/nfltr/relay/client/internal/leakcheck"
)

// TestMain fails the package when its tests leave goroutines running.
func TestMain(m *testing.M) {
	// quiclink.(*Node).Drain starts a goroutine that waits for the node's
	// sessions (n.sessions.Wait) and is not released when Drain returns at its
	// context's end with sessions still open. A bug in github.com/nfltr/link
	// (checked at v0.4.12); remove this ignore when link releases it.
	os.Exit(leakcheck.Run(m, "quiclink.(*Node).Drain.func2"))
}
