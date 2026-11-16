// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

import (
	"context"
	"errors"
	"sync/atomic"
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

// slowEnds is a mailbox whose pulls end a while after their context.
type slowEnds struct {
	Mailbox
	pulling atomic.Int32
}

func (s *slowEnds) Pull(ctx context.Context, box string, after uint64, max int, wait time.Duration) ([]mailboxclient.Envelope, string, error) {
	s.pulling.Add(1)
	defer s.pulling.Add(-1)
	envs, cursor, err := s.Mailbox.Pull(ctx, box, after, max, wait)
	if ctx.Err() != nil {
		time.Sleep(50 * time.Millisecond)
	}
	return envs, cursor, err
}

// The Keeper's Run returns only once its follows did, so nothing of it
// writes the machine's directory after (TempDir's cleanup found it not
// empty: TestFollowCRLTakesTheRevokePush, runner 04a89c6f).
func TestKeeperRunJoinsItsFollows(t *testing.T) {
	f := newFleet(t)
	mb := &slowEnds{Mailbox: f.relay}
	k := f.keeper()
	k.Mailbox = mb
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { defer close(done); k.Run(ctx) }()
	eventually(t, "both follows pulling", func() bool { return mb.pulling.Load() >= 2 })
	cancel()
	<-done
	if n := mb.pulling.Load(); n != 0 {
		t.Fatalf("Run returned with %d pull(s) of its follows still running", n)
	}
}
