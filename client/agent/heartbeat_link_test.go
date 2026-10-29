// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc/metadata"
)

// An agent answers the relay's heartbeats unless the relay takes its
// liveness from the agent link (agentwire.LinkLivenessKey) and the link is
// up: then the link's own liveness stands for it.
func TestHeartbeatAnsweredUnlessTheLinkStandsForIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header metadata.MD
		linkUp bool
		answer bool
	}{
		{"relay without link liveness, link up", nil, true, true},
		{"link liveness, link up", metadata.Pairs(agentwire.LinkLivenessKey, "1"), true, false},
		{"link liveness, link down", metadata.Pairs(agentwire.LinkLivenessKey, "1"), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				stream := &blockingStream{ctx: ctx, requests: make(chan *pb.HTTPProxyRequest, 1), sent: make(chan *pb.HTTPProxyResponse, 1), header: tc.header}
				routes, err := parseRoutes([]Route{{Backend: "http://127.0.0.1"}})
				if err != nil {
					t.Fatal(err)
				}
				cfg := Config{RequestTimeout: 5, Concurrency: 1, HeartbeatRecvThreshold: time.Hour}
				done := make(chan error, 1)
				go func() {
					done <- processStream(ctx, stream, "a", routes, cfg, newBackendClient(cfg), slog.New(slog.DiscardHandler), nil, nil, func() bool { return tc.linkUp })
				}()
				stream.requests <- &pb.HTTPProxyRequest{} // the relay's heartbeat
				synctest.Wait()
				var answered bool
				select {
				case <-stream.sent:
					answered = true
				default:
				}
				if answered != tc.answer {
					t.Fatalf("heartbeat answered = %v, want %v", answered, tc.answer)
				}
				cancel()
				<-done
			})
		})
	}
}
