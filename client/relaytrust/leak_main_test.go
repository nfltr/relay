// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package relaytrust

import (
	"os"
	"testing"

	"github.com/nfltr/relay/client/internal/leakcheck"
)

// TestMain fails the package when its tests leave goroutines running.
func TestMain(m *testing.M) { os.Exit(leakcheck.Run(m)) }
