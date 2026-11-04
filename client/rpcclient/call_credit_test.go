// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"testing"

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
