// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/nfltr/link/pathswitch"
)

// TestDirectReattachOfForgottenSessionEndsIt (lane DIRECTEND, nfltr
// conformance TestGroupDialHealth, TestGroupDial, TestE2EEPolicy/require
// under load): an agent that no longer holds a session (it forgot it, or
// restarted) answers its client's relayed re-attach with ABORT
// (pathswitch.Refuse), so the client's session ends and its Close returns
// at once. A plain stream reset left the client re-attaching once a second
// and its Close waiting out psCloseBound (30 s, the tests' own bound).
func TestDirectReattachOfForgottenSessionEndsIt(t *testing.T) {
	d := &directServer{sessions: map[*directSession]struct{}{}, logger: slog.New(slog.DiscardHandler)}
	key := []byte("session exporter, 32 bytes long.")
	first, gone := net.Pipe()
	_ = gone.Close() // the session's first stream: its agent end is gone
	cli := newPSConn(pathswitch.Client(pathStream{Conn: first}, PathRelayed, pathswitch.Config{Detach: time.Minute}), first)
	rs, rc := net.Pipe()
	go d.reattach(pathStream{Conn: rs})
	if _, err := cli.Move(pathStream{Conn: rc}, PathRelayed, func(e uint64) []byte { return pathToken(key, roleClient, e, nil) }); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { _ = cli.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second): // well under psCloseBound: a bound against the wait only
		t.Fatal("Close waited for an END ack from an agent that no longer holds the session")
	}
	select {
	case <-cli.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the refused session did not end")
	}
}
