// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"bytes"
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpcmd "google.golang.org/grpc/metadata"
)

// stalledRelay accepts an agent's tunnel and never reads from it, so a
// large frame's Send blocks on flow control and Recv on silence.
type stalledRelay struct {
	pb.UnimplementedDispatcherServer
	accepted chan struct{}
}

func (r *stalledRelay) AgentTunnel(s grpc.BidiStreamingServer[pb.TunnelFrame, pb.TunnelFrame]) error {
	_ = s.SendHeader(grpcmd.MD{}) // the relay's accept
	r.accepted <- struct{}{}
	<-s.Context().Done()
	return nil
}

// TestCloseWaitsForStreamCalls: a Dial'd agent's Close returns only after
// the Send and Recv it started on the stream returned, so none of its
// goroutines outlives Close.
func TestCloseWaitsForStreamCalls(t *testing.T) {
	relay := &stalledRelay{accepted: make(chan struct{}, 1)}
	// Fixed 64 KiB windows (no BDP growth): the 1 MiB frame below cannot pass.
	srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()), grpc.InitialWindowSize(64<<10), grpc.InitialConnWindowSize(64<<10))
	pb.RegisterDispatcherServer(srv, relay)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, err := Dial(ctx, lis.Addr().String(), WithAgentID("held-send"), WithAPIKey("k"), WithTLS(false))
	if err != nil {
		t.Fatal(err)
	}
	<-relay.accepted
	go func() {
		// The first frame takes the stream's write quota; the second's Send
		// waits for quota the stalled relay never frees.
		for range 2 {
			_ = a.sendFrame(&pb.TunnelFrame{TransactionId: "t1", Payload: make([]byte, 1<<20)})
		}
	}()
	waitGoroutine(t, "(*Agent).sendLoop.func", true)

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"(*Agent).sendLoop.func", "(*Agent).recvLoop.func"} {
		if stacksContain(fn) {
			t.Fatalf("%s still runs after Close returned", fn)
		}
	}
}

func stacksContain(fn string) bool {
	buf := make([]byte, 1<<20)
	return bytes.Contains(buf[:runtime.Stack(buf, true)], []byte(fn))
}

func waitGoroutine(t *testing.T, fn string, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for stacksContain(fn) != want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s (running=%v)", fn, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
