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
