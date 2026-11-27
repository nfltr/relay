// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgaudit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// logs is procs processes' Logs of one machine directory.
func logs(t *testing.T, procs int) []*Log {
	t.Helper()
	m := newMachine(t, "web", 1)
	m.cert.Subject = pkix.Name{CommonName: "web"}
	dir := t.TempDir()
	var ls []*Log
	for range procs {
		ls = append(ls, &Log{Dir: dir, Signer: func() (*x509.Certificate, ed25519.PrivateKey) { return m.cert, m.key }})
	}
	return ls
}

func opened(t *testing.T, l *Log, service string) func(End) {
	t.Helper()
	return l.Audit(Session{Service: service, Who: Who{Name: "ci-1"}, By: "rule group:ops machine:web " + service, Opened: time.Now()})
}

// records is dir's audit log, each line checked against the one before.
func records(t *testing.T, dir string) []Record {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, LogFile))
	if err != nil {
		t.Fatal(err)
	}
	var rs []Record
	var prev []byte
	for l := range bytes.Lines(data) {
		l = bytes.TrimSuffix(l, []byte("\n"))
		r, err := Parse(l)
		if err != nil {
			t.Fatalf("line %d: %v", len(rs)+1, err)
		}
		if prev != nil && r.Prev != Hash(prev) {
			t.Fatalf("line %d does not chain to the one before", len(rs)+1)
		}
		rs, prev = append(rs, r), l
	}
	return rs
}

func closes(rs []Record, session string) (n int, reason string) {
	for _, r := range rs {
		if r.Kind == KindClose && r.Session == session {
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
	ms := logs(t, 3)
	killed, live, next := ms[0], ms[1], ms[2]
	opened(t, killed, "pg")
	opened(t, killed, "ssh")(End{Closed: time.Now(), Reason: ReasonClosed})
	// A serving process's sessions keep its Machine (their ends hold it);
	// held here, or the GC closes its owner lock's file as a kill would.
	defer runtime.KeepAlive(opened(t, live, "web"))
	killed.release() // its process is gone: its owner lock is free
	if n, err := next.CloseLost(time.Now()); err != nil || n != 1 {
		t.Fatalf("CloseLost: %d closes, %v; want 1", n, err)
	}
	rs := records(t, next.Dir)
	if len(rs) != 5 {
		t.Fatalf("%d lines, want 5 (3 opens, 2 closes)", len(rs))
	}
	if n, reason := closes(rs, rs[0].Session); n != 1 || reason != ReasonLost {
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
	ms := logs(t, 2)
	killed, next := ms[0], ms[1]
	opened(t, killed, "pg")
	rs := records(t, killed.Dir)
	s := Session{ID: rs[0].Session, Service: rs[0].Service, Who: rs[0].Who, By: rs[0].By, Opened: rs[0].Opened}
	killed.line(s.Close(End{Closed: time.Now(), Reason: ReasonClosed})) // the close line, not the prune
	killed.add("intent-only")                                           // the owner file, not the open line
	killed.release()
	if n, err := next.CloseLost(time.Now()); err != nil || n != 0 {
		t.Fatalf("CloseLost: %d closes, %v; want none", n, err)
	}
	if n, _ := closes(records(t, next.Dir), s.ID); n != 1 {
		t.Fatalf("%d closes, want 1", n)
	}
	if left, _ := os.ReadDir(filepath.Join(next.Dir, OwnersDir)); len(left) != 0 {
		t.Fatalf("owner files left: %v", left)
	}
}

// Rotation drops what the issuer acknowledged, never the last line (the
// log goes on: OneLog, mutant rotate-all) or an open without its close
// (EveryOpenCloses, mutant rotate-drops-open), never past acked
// (NothingLost, mutant rotate-unacked).
func TestAuditRotationKeepsTheLog(t *testing.T) {
	m := logs(t, 1)[0]
	dir := m.Dir
	for range 3 {
		opened(t, m, "pg")(End{Closed: time.Now(), Reason: ReasonClosed})
	}
	end := opened(t, m, "ssh") // open: line 7
	opened(t, m, "pg")(End{Closed: time.Now(), Reason: ReasonClosed})
	data, _ := os.ReadFile(filepath.Join(dir, LogFile))
	offsets := []int64{0}
	for l := range bytes.Lines(data) {
		offsets = append(offsets, offsets[len(offsets)-1]+int64(len(l)))
	}
	before := records(t, dir)
	moved := int64(-1)
	cursor := func(cut int64) error { moved = cut; return nil }
	if cut, err := Rotate(dir, offsets[2], int64(len(data))+1, cursor); err != nil || cut != 0 {
		t.Fatalf("under the size: cut %d, %v", cut, err)
	}
	if cut, err := Rotate(dir, offsets[2], 1, cursor); err != nil || cut != offsets[2] || moved != cut {
		t.Fatalf("acked 2 lines: cut %d (cursor told %d), %v; want %d", cut, moved, err, offsets[2])
	}
	if cut, err := Rotate(dir, int64(len(data)), 1, cursor); err != nil || cut != offsets[6]-offsets[2] {
		t.Fatalf("all acked: cut %d, %v; want up to the open session (%d)", cut, err, offsets[6]-offsets[2])
	}
	end(End{Closed: time.Now(), Reason: ReasonClosed})
	data, _ = os.ReadFile(filepath.Join(dir, LogFile))
	last := int64(len(data)) - int64(len(bytes.TrimSuffix(data, []byte("\n")))-bytes.LastIndexByte(bytes.TrimSuffix(data, []byte("\n")), '\n'))
	if cut, err := Rotate(dir, int64(len(data)), 1, cursor); err != nil || cut != last {
		t.Fatalf("all acked and closed: cut %d, %v; want all but the last line (%d)", cut, err, last)
	}
	opened(t, m, "pg")
	rs := records(t, dir)
	if len(rs) != 2 || rs[0].Seq != uint64(len(before)+1) || rs[1].Seq != rs[0].Seq+1 || rs[1].Log != before[0].Log {
		t.Fatalf("after rotation: %d lines, seq %d.., log kept %v", len(rs), rs[0].Seq, rs[1].Log == before[0].Log)
	}
}
