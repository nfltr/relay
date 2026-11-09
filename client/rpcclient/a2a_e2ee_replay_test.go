// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"os"
	"testing"
	"time"
)

// The replay record survives its process (a new record on the same
// directory has every number written), reads past a torn append, keeps
// the previous slot and removes older ones.
func TestA2AReplayRecordSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	open := func() *a2aReplayRecord {
		r, err := openA2AReplayRecord(dir)
		if err != nil {
			t.Fatal(err)
		}
		r.now = clock
		t.Cleanup(r.close)
		return r
	}
	id := [a2aSessionIDLen]byte{7}
	r := open()
	r.mu.Lock()
	if err := r.write(id, 3); err != nil {
		t.Fatal(err)
	}
	r.mu.Unlock()
	// A crash mid-append: half a record, then the next process appends.
	f, err := os.OpenFile(r.path(r.slotNow()), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(a2aReplayEntry(id, 9)[:5]); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	r2 := open() // the restart
	r2.mu.Lock()
	defer r2.mu.Unlock()
	if err := r2.write(id, 4); err != nil {
		t.Fatal(err)
	}
	for c, want := range map[uint64]bool{3: true, 4: true, 9: false, 5: false} {
		if got := r2.has(id, c); got != want {
			t.Errorf("has(%d) = %v, want %v", c, got, want)
		}
	}
	if fi, err := os.Stat(r2.path(r2.slotNow())); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("record file: %v, %v; want mode 0600", fi, err)
	}

	now = now.Add(a2aReplaySlot) // the next slot: the previous one still answers
	if !r2.has(id, 3) {
		t.Error("a number of the previous slot forgotten")
	}
	old := r2.path(r2.slotNow() - 1)
	if err := r2.write(id, 5); err != nil {
		t.Fatal(err)
	}
	now = now.Add(a2aReplaySlot) // two slots on: the first file goes
	if err := r2.write(id, 6); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("a record older than the previous slot kept: %v", err)
	}
	if r2.has(id, 3) || !r2.has(id, 5) || !r2.has(id, 6) {
		t.Error("retention: want 3 gone, 5 and 6 kept")
	}
	// A file it cannot read counts as having every number (at most once).
	if err := os.Chmod(r2.path(r2.slotNow()), 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(r2.path(r2.slotNow()), 0o600) //nolint:errcheck
	if os.Getuid() != 0 && !r2.has(id, 99) {
		t.Error("an unreadable record answered a number as never taken")
	}
}

// A callee with no replay record offers no session: every call to it
// handshakes, so no call of it is ever resumed.
func TestA2AE2EENoRecordNoSessions(t *testing.T) {
	store := newTestStore(t, "m1")
	var log frameLog
	unrecorded := func(s AgentTunnel) *Agent {
		a := NewAgent("m1-node", s)
		if err := a.EnableA2AE2EE(store.machine("m1")); err != nil {
			panic(err)
		}
		return a
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	caller, _ := hostilePair(t, ctx, keyedAgent("hub", store), unrecorded, countingRelay(&log, nil))
	for i := range 3 {
		if got, err := invokeCtx(t, caller, "m1-node", "q"); err != nil || string(got) != "echo:q" {
			t.Fatalf("call %d = %q, %v", i, got, err)
		}
	}
	if n, r := log.count(true, a2aE2EEInitMessageType), log.count(true, a2aE2EEResumeMessageType); n != 3 || r != 0 {
		t.Fatalf("inits %d, resumes %d; want 3 and 0", n, r)
	}
}
