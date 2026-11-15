// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nfltr/relay/client/mailboxclient"
)

// failingPulls fails its first n pulls and reports every pull's start.
type failingPulls struct {
	Mailbox
	n     int
	calls chan int
}

func (f *failingPulls) Pull(ctx context.Context, _ string, _ uint64, _ int, _ time.Duration) ([]mailboxclient.Envelope, string, error) {
	f.calls <- 1
	if f.n > 0 {
		f.n--
		return nil, "", errors.New("http2: client connection lost")
	}
	<-ctx.Done()
	return nil, "", ctx.Err()
}

// A pull failed by a dead connection (a NAT that changed the port) is
// pulled again at once, not after retryWait, so a push lands near the
// mailbox client's ping bound. A second failure in a row waits retryWait: no hot loop.
// Every follow (the Keeper's CRL and root) is this loop.
func TestFollowPullsAgainAtOnceAfterAFailedPull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mb := &failingPulls{n: 2, calls: make(chan int, 8)}
	go follow(ctx, mb, "org.x.crl", time.Hour, func([]byte) error { return nil }, nil, quiet())
	<-mb.calls // the first pull, failed
	select {
	case <-mb.calls:
	case <-time.After(retryWait / 3):
		t.Fatalf("no pull within %s of a failed one (retryWait %s)", retryWait/3, retryWait)
	}
	select {
	case <-mb.calls:
		t.Fatal("a second failure in a row was pulled again at once")
	case <-time.After(300 * time.Millisecond):
	}
}
