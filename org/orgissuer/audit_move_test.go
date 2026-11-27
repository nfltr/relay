// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgissuer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The issuer's session audit files move with it (spec/MoveAudit.tla
// AckedHeld; mutant bundle-no-sessions, the code before): the lines a
// machine was answered for are the issuer's, so the new machine holds
// them, where it stands per machine, the sink's cursor and setting. A move
// back sets the tombstone's copies aside.
func TestMoveCarriesTheSessionAudit(t *testing.T) {
	old, pin := newOrgConfig(t)
	audit := map[string]string{
		"sessions.jsonl":      "{\"rec\":{\"seq\":1}}\n",
		"sessions-heads.json": `{"m1":{}}`,
		"sessions.sink":       `{"sink":"/var/log/a","offset":17}`,
		"config.json":         `{"audit":{"sink":"/var/log/a"}}`,
	}
	write := func(conf string, files map[string]string) {
		t.Helper()
		for f, data := range files {
			if err := os.WriteFile(filepath.Join(Dir(conf), f), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	check := func(conf string, files map[string]string) {
		t.Helper()
		for f, want := range files {
			got, err := os.ReadFile(filepath.Join(Dir(conf), f))
			if err != nil || !bytes.Equal(got, []byte(want)) {
				t.Errorf("%s after the move: %q, %v; want %q", f, got, err, want)
			}
		}
	}
	write(old, audit)
	conf, keyPath, rk := receiver(t)
	sealed, err := Send(old, rk, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(conf, keyPath, sealed, pin, t0); err != nil {
		t.Fatal(err)
	}
	check(conf, audit)

	// The new issuer took more; the organisation moves back over the
	// tombstone, whose older copies go aside.
	grown := map[string]string{"sessions.jsonl": audit["sessions.jsonl"] + "{\"rec\":{\"seq\":2}}\n", "sessions-heads.json": `{"m1":{"logs":{}}}`}
	write(conf, grown)
	back := filepath.Join(old, ReceiveKeyFile)
	bk, err := LoadReceiveKey(back)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = Send(conf, ReceiveKey{Pub: bk.PublicKey()}, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(old, back, sealed, pin, t0.Add(time.Minute)); err != nil {
		t.Fatalf("the move back: %v", err)
	}
	check(old, grown)
}
