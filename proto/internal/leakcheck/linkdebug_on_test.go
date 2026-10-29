// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build linkdebug

package leakcheck

import (
	"fmt"
	"os"
	"testing"
)

// TestLinkDebugReportFails: built with -tags linkdebug, a "link debug:" line
// on stderr is counted (scripts/test-linkdebug.sh runs this package).
func TestLinkDebugReportFails(t *testing.T) {
	fmt.Fprint(os.Stderr, "link debug: session 1 opened and garbage-collected, never closed (leakcheck's own test)\n")
	if n := linkDebugReports(); n != 1 {
		t.Fatalf("%d link debug reports counted, want 1", n)
	}
}
