// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTokenFileIsReadAtEveryAttempt: a token another process rewrites is
// what the next connection attempt presents; a bad file fails the attempt.
func TestTokenFileIsReadAtEveryAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	a := New(Config{AgentID: "x", Token: "static", TokenFile: path}).(*agent)
	if _, err := a.token(); err == nil {
		t.Fatal("a missing credential file did not fail the attempt")
	}
	for _, tok := range []string{"first.jwt.token", "second.jwt.token"} {
		if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := a.token(); err != nil || got != tok {
			t.Fatalf("token = %q, %v; want %q", got, err, tok)
		}
	}
	if err := os.WriteFile(path, []byte("two tokens"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.token(); err == nil {
		t.Fatal("a file of two words was taken as a credential")
	}
	if got, _ := New(Config{AgentID: "x", Token: "static"}).(*agent).token(); got != "static" {
		t.Fatalf("without a file the key is %q, want Token", got)
	}
}
