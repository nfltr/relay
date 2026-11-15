// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgfiles

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReplacesWriteNewKeeps(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := WriteNew(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Fatalf("WriteNew replaced the file: %q", b)
	}
	if err := Write(p, []byte("three"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "three" || fi.Mode().Perm() != 0o644 {
		t.Fatalf("Write: %q %v", b, fi.Mode().Perm())
	}
	if m, _ := filepath.Glob(p + ".*.tmp"); len(m) != 0 {
		t.Fatalf("left %v", m)
	}
}

func TestTryLockRefusesAHeldLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	unlock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TryLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("TryLock of a held lock = %v, want ErrLocked", err)
	}
	unlock()
	again, err := TryLock(path)
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	again()
}
