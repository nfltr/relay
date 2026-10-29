// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"os"
	"testing"
)

func TestPresharedKeyFromFileRejectsShortSecrets(t *testing.T) {
	path := t.TempDir() + "/short"
	if err := os.WriteFile(path, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PresharedKeyFromFile(path); err == nil {
		t.Fatal("a short pairing secret was accepted")
	}
}
