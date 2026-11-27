// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"
	"time"
)

// countAcker is an acker that has written n bytes and records the count
// a wait asks for.
type countAcker struct {
	n    uint64
	want chan uint64
}

func (a countAcker) Written() uint64 { return a.n }
func (a countAcker) WaitAcked(n uint64, _ time.Duration) bool {
	a.want <- n
	return true
}

// TestAckedEndWaitsForTheEnd (lane ENDACK; link spec/DirectPath.tla
// EndTruth): a direct path's acked end waits for the peer's
// acknowledgement of every byte and of the END (position Written()+1),
// which pathswitch gives only once the peer's program read it; waiting
// for the bytes alone let a Close return nil while the peer's program
// could still fail (pipe TestReceiverStopsAfterArrival, direct).
func TestAckedEndWaitsForTheEnd(t *testing.T) {
	tc, peer := newQueuePipe()
	t.Cleanup(func() { _ = peer.Close() })
	a := countAcker{n: 7, want: make(chan uint64, 1)}
	if err := (ackedEnd{tc, a, newCloseSync()}).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := <-a.want; got != 8 {
		t.Fatalf("WaitAcked(%d), want %d: the END is position Written()+1", got, 8)
	}
}
