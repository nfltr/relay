// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestDocsNameNoGhosts: the doc comments of this module's public packages
// name only what exists: no unexported identifier, no member a type lacks,
// no name api/proto-*.txt records as removed (proto/internal/tools/docnames,
// as link's test of the same name; lane RELAYAPI found 48 such references).
func TestDocsNameNoGhosts(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "docnames")
	build := exec.Command("go", "build", "-o", bin, "./internal/tools/docnames")
	build.Dir = "."
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build docnames: %v\n%s", err, out)
	}
	run := exec.Command(bin, "proto")
	run.Dir = ".."
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docnames: %v\n%s", err, out)
	}
}
