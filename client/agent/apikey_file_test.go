// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAPIKeyFileIsReadAtEveryAttempt: a token another process rewrites is
// what the next connection attempt presents; a bad file fails the attempt.
func TestAPIKeyFileIsReadAtEveryAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	a := New(Config{AgentID: "x", APIKey: "static", APIKeyFile: path}).(*agent)
	if _, err := a.apiKey(); err == nil {
		t.Fatal("a missing credential file did not fail the attempt")
	}
	for _, tok := range []string{"first.jwt.token", "second.jwt.token"} {
		if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := a.apiKey(); err != nil || got != tok {
			t.Fatalf("apiKey = %q, %v; want %q", got, err, tok)
		}
	}
	if err := os.WriteFile(path, []byte("two tokens"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.apiKey(); err == nil {
		t.Fatal("a file of two words was taken as a credential")
	}
	if got, _ := New(Config{AgentID: "x", APIKey: "static"}).(*agent).apiKey(); got != "static" {
		t.Fatalf("without a file the key is %q, want APIKey", got)
	}
}
