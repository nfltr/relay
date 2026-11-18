// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"
	"time"

	"github.com/nfltr/link/pathswitch"
)

// TestDirectEndedSessionStaysFindable: a session that ended at the agent
// stays findable for the detach bound, so a client whose path died (or
// moved) before the agent's last ACK and FIN reached it has its re-attach
// answered by pathswitch's Attach (left: the count and FIN; reset: the
// ABORT; link spec/DirectPath.tla RLeftAnswer, SLeftAnswer), never reset
// as a stranger's, which left the client re-attaching until its own
// detach bound (lane FLAKEGROUP: TestGroupDial's dials hung 30 s on a
// loaded machine, the agent forgetting each session at its Done). After
// the bound it is forgotten.
func TestDirectEndedSessionStaysFindable(t *testing.T) {
	d := &directServer{sessions: map[*directSession]struct{}{}, detach: 300 * time.Millisecond}
	key, qk := []byte("session exporter, 32 bytes long."), []byte("quic exporter, 32 bytes long....")
	c := pathswitch.Server(pathStream{Conn: nopConn{}}, PathRelayed, pathswitch.Config{Detach: 10 * time.Millisecond})
	s := d.register(c, key)
	c.Abort()             // its Done within the 10 ms bound
	for !s.ended.Load() { // the registry saw the end
		time.Sleep(time.Millisecond)
	}
	o := pathswitch.Open{Epoch: 2, Token: pathToken(key, roleClient, 2, qk)}
	if d.find(o, qk) == nil {
		t.Fatal("the agent forgot the session at its end: its client's re-attach is reset, not answered")
	}
	deadline := time.Now().Add(5 * time.Second)
	for d.find(o, qk) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the ended session is still findable past the detach bound")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
