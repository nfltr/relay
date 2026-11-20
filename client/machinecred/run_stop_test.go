// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package machinecred

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// holdersNow is c's holder count.
func (c *Credential) holdersNow() int {
	c.runMu.Lock()
	defer c.runMu.Unlock()
	return c.holders
}

// renewerRuns: a renewer goroutine of this package is alive.
func renewerRuns() bool {
	buf := make([]byte, 1<<20)
	return strings.Contains(string(buf[:runtime.Stack(buf, true)]), "machinecred.(*Credential).renew(")
}

// TestRunStopJoinsTheRenewer: the renewer runs while some caller holds it
// (Run until its stop or its context's end), and the last holder's stop
// returns only once the renewer has finished, mid-renewal included: nothing
// of it renews or writes the machine's directory after (lane PINSCOPE: it
// was fire-and-forget, and nfltr's OrgRelay started it with a context that
// never ends).
func TestRunStopJoinsTheRenewer(t *testing.T) {
	inRenew, quit := make(chan struct{}, 16), make(chan struct{})
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inRenew <- struct{}{}
		select { // the renewal hangs until its caller gives up
		case <-r.Context().Done():
		case <-quit:
		}
	}))
	defer relay.Close()
	defer close(quit)
	c := renewDue(t, relay.URL)

	ctx, cancel := context.WithCancel(context.Background())
	stopA := c.Run(context.Background(), nil) // a holder whose context never ends
	_ = c.Run(ctx, nil)                       // released by its context
	<-inRenew
	if !c.Renewing() || c.holdersNow() != 2 {
		t.Fatal("two holders, not renewing")
	}
	cancel()
	for deadline := time.Now().Add(10 * time.Second); c.holdersNow() != 1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) { // only against a hang
			t.Fatal("the ended context did not release its hold")
		}
	}
	if !renewerRuns() {
		t.Fatal("one holder's context ended and the renewer stopped for the other")
	}
	stopA()
	if renewerRuns() {
		t.Fatal("the last holder's stop returned while the renewer still runs")
	}
	if c.holdersNow() != 0 {
		t.Fatal("no Run holds it, still counted")
	}
	stopA() // a second stop is a no-op

	// It runs again for a new holder.
	stop := c.Run(context.Background(), nil)
	<-inRenew
	stop()
	if renewerRuns() {
		t.Fatal("a restarted renewer outlived its stop")
	}
}
