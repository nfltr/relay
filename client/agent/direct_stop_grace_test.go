// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nfltr/link/pathswitch"
)

// TestDirectStopsWaitOneGrace (lane SENDCUT, nfltr-send
// docs/reliability.md cut-receiver-*-direct): a stopping agent runs
// directServer.stop three times (its primary's drain, its cycle's end,
// ServiceTable.Close). A session whose peer was killed never answers the
// ABORT, so each stop waited its own directCutGrace for it, and the first
// two the drain too: a --once nfltr-send whose earlier receiver was killed
// exited 21 s after its transfer. The grace runs once, from the session's
// first reset, and the drain ends at the first stop: the three stops
// together take one grace.
func TestDirectStopsWaitOneGrace(t *testing.T) {
	t.Parallel()
	detach := 2*directCutGrace + time.Second // the dead peer's session outlives two graces
	d := &directServer{sessions: map[*directSession]struct{}{}, detach: detach}
	sc, dead := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, dead) }() // the path delivers; the peer never answers
	s := pathswitch.Server(pathStream{Conn: sc}, PathRelayed, pathswitch.Config{Detach: detach})
	d.registerSession(&directSession{c: s})

	ended, cancel := context.WithCancel(t.Context())
	cancel() // the agent's drain ended
	table, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	start := time.Now()
	d.stop(ended) // the primary's
	d.stop(ended) // the cycle's end
	d.stop(table) // ServiceTable.Close
	if took := time.Since(start); took > directCutGrace+time.Second {
		t.Errorf("three stops took %v with a dead direct peer, want one grace (%v)", took, directCutGrace)
	}
	<-s.Done() // its detach bound: nothing left running
	_ = dead.Close()
}

// TestDirectTargetResetResetsTheSession (lane SENDCUT): nfnet's
// Listener.Close resets its accepted Conns, then stops the agent. A
// session whose direct peer was killed did not hear of that reset: Join's
// copy toward the peer waited on the peer's window and never read the
// target's reset, so the session held the agent's drain to its bound and
// its grace started only after. A target's reset resets its direct session
// at once, and the drain does not wait for a session already reset: the
// stop ends one grace after the reset.
func TestDirectTargetResetResetsTheSession(t *testing.T) {
	t.Parallel()
	detach := 2*directCutGrace + time.Second
	d := &directServer{sessions: map[*directSession]struct{}{}, detach: detach}
	sc, dead := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, dead) }() // the path delivers; the peer never answers
	s := pathswitch.Server(pathStream{Conn: sc}, PathRelayed, pathswitch.Config{Detach: detach})
	user, target := newQueuePipe()
	setDirect(target, d.registerSession(&directSession{c: s}))

	start := time.Now()
	_ = user.Reset()
	drain, cancel := context.WithTimeout(t.Context(), directCutGrace+2*time.Second)
	defer cancel()
	d.stop(drain)
	if took := time.Since(start); took > directCutGrace+time.Second {
		t.Errorf("the stop ended %v after the target's reset, want one grace (%v)", took, directCutGrace)
	}
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Error("the session reads on after its target's reset")
	}
	<-s.Done()
	_ = dead.Close()
}

// TestDirectStopRefusesLateSessions (lane STOPGAP, spec/AgentStop.tla
// late-unreset): a session registered once a stop's drain ended was put
// in the table after the stop took its sessions, so no stop reset it; it
// could move to its direct path and live on at its peer, past the
// process's exit, until the detach bound (or a later stop waited a fresh
// grace for it, past the stop's bound). It is refused: reset at once and
// left out of the table, so no stop waits for it.
func TestDirectStopRefusesLateSessions(t *testing.T) {
	t.Parallel()
	d := &directServer{sessions: map[*directSession]struct{}{}, detach: time.Minute}
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	d.stop(ended) // the primary's: its drain ended

	sc, peer := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	defer peer.Close() //nolint:errcheck
	s := pathswitch.Server(pathStream{Conn: sc}, PathRelayed, pathswitch.Config{Detach: time.Minute})
	ds := d.registerSession(&directSession{c: s})
	select {
	case <-ds.aborted:
	case <-time.After(time.Second):
		t.Fatal("a session registered after the stop's drain is not reset")
	}
	if len(d.liveSessions()) != 0 {
		t.Error("a refused session is in the table")
	}
	start := time.Now()
	d.stop(ended) // the cycle's end: nothing of its own to wait for
	if took := time.Since(start); took > directCutGrace/2 {
		t.Errorf("a later stop took %v for a refused session, want none", took)
	}
}
