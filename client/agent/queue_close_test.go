// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/link"
)

// Lane DIRECTCLOSE, PIPEMATRIX defect 1 (queue_close.go): Accept's
// conn's Close on a direct path returns once the peer acknowledged every
// byte and the end, an error when it could not.

// queuedPair is a session through a SessionQueue: Accept's conn and the
// agent's end the session's goroutine joins.
func queuedPair(t *testing.T) (user, agentEnd *QueueConn) {
	t.Helper()
	q := NewSessionQueue(1)
	acc := make(chan *QueueConn, 1)
	go func() {
		c, err := q.Accept()
		if err != nil {
			t.Error(err)
		}
		acc <- c.(*QueueConn)
	}()
	c, _, err := q.enter(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return <-acc, c.(*QueueConn)
}

// fakeAcker acknowledges when the test says (ok).
type fakeAcker struct{ ok chan bool }

func (fakeAcker) Written() uint64                        { return 0 }
func (a fakeAcker) WaitAcked(uint64, time.Duration) bool { return <-a.ok }

// joined is a queued session joined (joinTarget) to a direct-path
// session whose peer reads everything: its Accept conn and its acker.
func joined(t *testing.T) (*QueueConn, fakeAcker) {
	t.Helper()
	user, agentEnd := queuedPair(t)
	tc, peer := newQueuePipe()
	a := fakeAcker{make(chan bool, 1)}
	go func() { _ = joinTarget(tc, a, agentEnd) }()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	t.Cleanup(func() { _ = peer.Close() })
	return user, a
}

func closeAsync(c *QueueConn) <-chan error {
	ret := make(chan error, 1)
	go func() { ret <- c.Close() }()
	return ret
}

func notYet(t *testing.T, ret <-chan error) {
	t.Helper()
	select {
	case err := <-ret:
		t.Fatalf("Close returned %v before the peer acknowledged its end", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func waitRet(t *testing.T, ret <-chan error, want error) {
	t.Helper()
	select {
	case err := <-ret:
		if !errors.Is(err, want) {
			t.Fatalf("Close: %v, want %v", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close still waits 5 s after the acknowledgement")
	}
}

func TestQueueCloseWaitsForDelivery(t *testing.T) {
	for _, acked := range []bool{true, false} {
		user, a := joined(t)
		if _, err := user.Write([]byte("tail")); err != nil {
			t.Fatal(err)
		}
		ret := closeAsync(user)
		notYet(t, ret)
		a.ok <- acked
		want := error(nil)
		if !acked {
			want = link.ErrReset
		}
		waitRet(t, ret, want)
	}
}

// A Reset while Close waits (Listener.Close at a signal) cuts the direct
// session, which ends the wait (pathswitch: the abort fails WaitAcked).
func TestQueueResetCutsAWaitingClose(t *testing.T) {
	user, a := joined(t)
	var once sync.Once
	f := func() { once.Do(func() { a.ok <- false }) } // the direct session's abort
	user.cut.Store(&f)
	ret := closeAsync(user)
	notYet(t, ret)
	_ = user.Reset()
	waitRet(t, ret, link.ErrReset)
}

// A queued session joined without a report (relayed: a plain Join uses
// the agent's end) closes at once, as before; one Close while its session
// is not joined yet waits for the join (a direct path's report).
func TestQueueCloseUnreportedReturnsAtOnce(t *testing.T) {
	user, agentEnd := queuedPair(t)
	ret := closeAsync(user)
	notYet(t, ret)
	_, _ = agentEnd.Read(make([]byte, 1)) // Join's copy begins
	waitRet(t, ret, nil)
}
