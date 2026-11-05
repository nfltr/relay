// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
)

// A served call's credit lives from its stream to its end (end), with no
// context callback per call (lane CALLCREDIT2: context.AfterFunc cost
// allocations on every served call): a stream and its end allocate at
// most what the stream, its context and its credit need. And end forgets
// the credit: a Send waiting for it returns.
func TestServedCallCreditEndsWithTheCall(t *testing.T) {
	a := NewAgent("agent-a", newMockStream(t.Context()))
	defer a.Close() //nolint:errcheck
	msg := &pb.TunnelFrame{TransactionId: "txn", Routing: &pb.RoutingInfo{AgentId: "agent-b"}}

	if allocs := testing.AllocsPerRun(100, func() { a.newServerStream(msg, nil, nil).end() }); allocs > 8 {
		t.Fatalf("a served call's stream and end allocate %.0f times, want <= 8", allocs)
	}

	ss := a.newServerStream(msg, nil, nil)
	for range ResponseWindow {
		if !a.serveCredit.Acquire(ss.txnID, 1) {
			t.Fatal("Acquire within the window failed")
		}
	}
	done := make(chan bool)
	go func() { done <- a.serveCredit.Acquire(ss.txnID, 1) }()
	ss.end()
	if <-done {
		t.Fatal("a Send waiting for credit took some after the call ended")
	}
}

// Several goroutines may Send on one served call (a remote-exec handler's
// stdout and stderr). Two of them waiting for credit, one grant of two
// sends both: a grant reaches every waiting sender, not only the one
// link.Credit's wake token woke (spec/CallCreditSenders.tla
// NoStrandedWaiter; lane FLAKECC: TestConcurrentServerStreamSend stalled
// at 427 of 500 frames with credit there).
func TestConcurrentSendersShareAGrant(t *testing.T) {
	a := NewAgent("agent-a", newMockStream(t.Context()))
	defer a.Close() //nolint:errcheck
	ss := a.newServerStream(&pb.TunnelFrame{TransactionId: "txn", Routing: &pb.RoutingInfo{AgentId: "agent-b"}}, nil, nil)
	defer ss.end()
	for range ResponseWindow {
		if !a.serveCredit.Acquire(ss.txnID, 1) {
			t.Fatal("Acquire within the window failed")
		}
	}
	done := make(chan error, 2)
	for range 2 {
		go func() { done <- ss.Send([]byte("x")) }()
	}
	waitSendersParked(t, 2)
	if err := a.serveCredit.Grant(ss.txnID, 2); err != nil { // handleWindow's
		t.Fatal(err)
	}
	bound := time.After(5 * time.Second) // only against a hang
	for i := range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Send %d: %v", i, err)
			}
		case <-bound:
			t.Fatalf("%d of 2 Sends returned; the other waits with the grant's credit there", i)
		}
	}
}

// waitSendersParked waits until n goroutines in serverStream.Send are
// blocked waiting for the call's credit (in link.Credit.acquire's select).
func waitSendersParked(t *testing.T, n int) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		parked := 0
		for _, g := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
			if strings.Contains(g, "(*serverStream).Send") && strings.Contains(g, "[select") &&
				strings.Contains(g, "(*Credit).acquire") {
				parked++
			}
		}
		if parked >= n {
			return
		}
	}
	t.Fatalf("fewer than %d senders waiting for credit", n)
}
