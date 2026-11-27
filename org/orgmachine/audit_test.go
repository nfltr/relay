// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgmachine_test

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgmachine/orgmachinetest"
)

// auditMachine is a machine's directory enrolled, opened by procs
// processes (each its own Machine on the directory).
func auditMachine(t *testing.T, procs int) []*orgmachine.Machine {
	t.Helper()
	now := time.Now()
	o := orgmachinetest.New(t, now)
	dir := filepath.Join(t.TempDir(), "web")
	o.Enrol(t, dir, "web", now, "web")
	var ms []*orgmachine.Machine
	for range procs {
		ms = append(ms, open(t, dir))
	}
	return ms
}

func opened(t *testing.T, m *orgmachine.Machine, service string) func(orgaudit.End) {
	t.Helper()
	leaf, _ := m.Current()
	return m.Audit([]*x509.Certificate{leaf, m.Issuer()}, service, []string{service}, time.Now())
}

// records is dir's audit log, each line checked against the one before.
func records(t *testing.T, dir string) []orgaudit.Record {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, orgmachine.AuditFile))
	if err != nil {
		t.Fatal(err)
	}
	var rs []orgaudit.Record
	var prev []byte
	for l := range bytes.Lines(data) {
		l = bytes.TrimSuffix(l, []byte("\n"))
		r, err := orgaudit.Parse(l)
		if err != nil {
			t.Fatalf("line %d: %v", len(rs)+1, err)
		}
		if prev != nil && r.Prev != orgaudit.Hash(prev) {
			t.Fatalf("line %d does not chain to the one before", len(rs)+1)
		}
		rs, prev = append(rs, r), l
	}
	return rs
}

func closes(rs []orgaudit.Record, session string) (n int, reason string) {
	for _, r := range rs {
		if r.Kind == orgaudit.KindClose && r.Session == session {
			n, reason = n+1, r.Reason
		}
	}
	return n, reason
}

// A process killed mid-session leaves an open; the machine's next process
// closes it lost, once (spec/AuditLog.tla EveryOpenCloses, AtMostOneClose;
// mutant no-recovery, the code before). A live process's session stays
// open (LiveOpenNotClosed; mutant recover-live).
func TestKilledProcessSessionClosedLost(t *testing.T) {
	ms := auditMachine(t, 3)
	killed, live, next := ms[0], ms[1], ms[2]
	opened(t, killed, "pg")
	opened(t, killed, "ssh")(orgaudit.End{Closed: time.Now(), Reason: orgaudit.ReasonClosed})
	// A serving process's sessions keep its Machine (their ends hold it);
	// held here, or the GC closes its owner lock's file as a kill would.
	defer runtime.KeepAlive(opened(t, live, "web"))
	orgmachine.KillOwner(killed) // its process is gone: its owner lock is free
	if n, err := next.CloseLost(time.Now()); err != nil || n != 1 {
		t.Fatalf("CloseLost: %d closes, %v; want 1", n, err)
	}
	rs := records(t, next.Dir())
	if len(rs) != 5 {
		t.Fatalf("%d lines, want 5 (3 opens, 2 closes)", len(rs))
	}
	if n, reason := closes(rs, rs[0].Session); n != 1 || reason != orgaudit.ReasonLost {
		t.Fatalf("the killed process's open session: %d closes (%s), want one lost", n, reason)
	}
	if n, _ := closes(rs, rs[3].Session); n != 0 {
		t.Fatal("the live process's session was closed")
	}
	if n, err := next.CloseLost(time.Now()); err != nil || n != 0 {
		t.Fatalf("CloseLost again: %d closes, %v; want none", n, err)
	}
}

// A process killed between its close line and its owner file's prune
// (W_CloseThenKilled), or between its owner file and its open line
// (W_IntentOnly), gets no close from recovery: the log says what happened
// (mutant recover-no-log-check).
func TestKilledBetweenStepsClosedOnce(t *testing.T) {
	ms := auditMachine(t, 2)
	killed, next := ms[0], ms[1]
	opened(t, killed, "pg")
	rs := records(t, killed.Dir())
	s := orgaudit.Session{ID: rs[0].Session, Service: rs[0].Service, Who: rs[0].Who, By: rs[0].By, Opened: rs[0].Opened}
	orgmachine.WriteAudit(killed, s.Close(orgaudit.End{Closed: time.Now(), Reason: orgaudit.ReasonClosed})) // the close line, not the prune
	orgmachine.AddOwned(killed, "intent-only")                                                              // the owner file, not the open line
	orgmachine.KillOwner(killed)
	if n, err := next.CloseLost(time.Now()); err != nil || n != 0 {
		t.Fatalf("CloseLost: %d closes, %v; want none", n, err)
	}
	if n, _ := closes(records(t, next.Dir()), s.ID); n != 1 {
		t.Fatalf("%d closes, want 1", n)
	}
	if left, _ := os.ReadDir(filepath.Join(next.Dir(), orgmachine.OwnersDir)); len(left) != 0 {
		t.Fatalf("owner files left: %v", left)
	}
}

// Rotation drops what the issuer acknowledged, never the last line (the
// log goes on: OneLog, mutant rotate-all) or an open without its close
// (EveryOpenCloses, mutant rotate-drops-open), never past acked
// (NothingLost, mutant rotate-unacked).
func TestAuditRotationKeepsTheLog(t *testing.T) {
	m := auditMachine(t, 1)[0]
	dir := m.Dir()
	for range 3 {
		opened(t, m, "pg")(orgaudit.End{Closed: time.Now(), Reason: orgaudit.ReasonClosed})
	}
	end := opened(t, m, "ssh") // open: line 7
	opened(t, m, "pg")(orgaudit.End{Closed: time.Now(), Reason: orgaudit.ReasonClosed})
	data, _ := os.ReadFile(filepath.Join(dir, orgmachine.AuditFile))
	offsets := []int64{0}
	for l := range bytes.Lines(data) {
		offsets = append(offsets, offsets[len(offsets)-1]+int64(len(l)))
	}
	before := records(t, dir)
	moved := int64(-1)
	cursor := func(cut int64) error { moved = cut; return nil }
	if cut, err := orgmachine.RotateAudit(dir, offsets[2], int64(len(data))+1, cursor); err != nil || cut != 0 {
		t.Fatalf("under the size: cut %d, %v", cut, err)
	}
	if cut, err := orgmachine.RotateAudit(dir, offsets[2], 1, cursor); err != nil || cut != offsets[2] || moved != cut {
		t.Fatalf("acked 2 lines: cut %d (cursor told %d), %v; want %d", cut, moved, err, offsets[2])
	}
	if cut, err := orgmachine.RotateAudit(dir, int64(len(data)), 1, cursor); err != nil || cut != offsets[6]-offsets[2] {
		t.Fatalf("all acked: cut %d, %v; want up to the open session (%d)", cut, err, offsets[6]-offsets[2])
	}
	end(orgaudit.End{Closed: time.Now(), Reason: orgaudit.ReasonClosed})
	data, _ = os.ReadFile(filepath.Join(dir, orgmachine.AuditFile))
	last := int64(len(data)) - int64(len(bytes.TrimSuffix(data, []byte("\n")))-bytes.LastIndexByte(bytes.TrimSuffix(data, []byte("\n")), '\n'))
	if cut, err := orgmachine.RotateAudit(dir, int64(len(data)), 1, cursor); err != nil || cut != last {
		t.Fatalf("all acked and closed: cut %d, %v; want all but the last line (%d)", cut, err, last)
	}
	opened(t, m, "pg")
	rs := records(t, dir)
	if len(rs) != 2 || rs[0].Seq != uint64(len(before)+1) || rs[1].Seq != rs[0].Seq+1 || rs[1].Log != before[0].Log {
		t.Fatalf("after rotation: %d lines, seq %d.., log kept %v", len(rs), rs[0].Seq, rs[1].Log == before[0].Log)
	}
}
