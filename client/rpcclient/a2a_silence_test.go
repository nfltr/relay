// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	grpcmd "google.golang.org/grpc/metadata"
)

// headerStream is a tunnel whose relay states its heartbeat in its headers.
type headerStream struct {
	*mockStream
	header grpcmd.MD
}

func (s headerStream) Header() (grpcmd.MD, error) { return s.header, nil }

// A relay that states its heartbeat and then goes silent (it died, or the
// path dropped without a FIN) ends the connection after the liveness's wait;
// every frame, heartbeat or data, restarts the count.
func TestAgentEndsAfterRelaySilence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := newMockStream(t.Context())
		// The default liveness: the stated 5s plus 10s.
		a := NewAgent("a", headerStream{ms, grpcmd.Pairs(agentwire.HeartbeatPairs(agentwire.HeartbeatKey, 5*time.Second)...)})
		defer a.Close() //nolint:errcheck
		start := time.Now()
		time.Sleep(10 * time.Second)
		ms.recvCh <- &pb.TunnelFrame{} // a heartbeat
		<-a.Done()
		if got := time.Since(start); got != 25*time.Second {
			t.Fatalf("connection ended after %s, want 25s (the heartbeat at 10s, then 15s of silence)", got)
		}
		if err := a.Err(); err == nil || !strings.Contains(err.Error(), "no frame from the relay for 15s") || !errors.Is(err, ErrRelaySilent) || FatalClass(err) != NotFatal || !strings.HasSuffix(err.Error(), ": connection lost") {
			t.Fatalf("Err = %v", err)
		}
	})
}

// A relay that states no heartbeat (older, or heartbeats off) leaves the
// connection to the transport keepalive.
func TestAgentWithoutRelayHeartbeatWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := newMockStream(t.Context())
		a := NewAgent("a", headerStream{ms, nil})
		time.Sleep(time.Hour)
		select {
		case <-a.Done():
			t.Fatalf("connection ended: %v", a.Err())
		default:
		}
		_ = a.Close()
	})
}
