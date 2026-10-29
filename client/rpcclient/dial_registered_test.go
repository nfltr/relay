// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcmd "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// registeringRelay accepts an AgentTunnel as the relay does: it registers
// the agent (after delay), then sends its headers; refuse refuses instead.
type registeringRelay struct {
	pb.UnimplementedDispatcherServer
	delay      time.Duration
	refuse     bool
	registered atomic.Bool
}

func (r *registeringRelay) AgentTunnel(s grpc.BidiStreamingServer[pb.TunnelFrame, pb.TunnelFrame]) error {
	if r.refuse {
		return status.Error(codes.PermissionDenied, "no")
	}
	time.Sleep(r.delay)
	r.registered.Store(true)
	_ = s.SendHeader(grpcmd.MD{})
	<-s.Context().Done()
	return nil
}

func serveRelay(t *testing.T, r pb.DispatcherServer) string {
	t.Helper()
	srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	pb.RegisterDispatcherServer(srv, r)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// Dial returns once the relay has registered the agent (its accept
// headers), so a caller can route to the agent at once; a refused
// credential is Dial's error, of its fatal class.
func TestDialReturnsOnceTheRelayRegisteredTheAgent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := &registeringRelay{delay: 300 * time.Millisecond}
	a, err := Dial(ctx, serveRelay(t, r), WithAgentID("x"), WithAPIKey("k"), WithTLS(false))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close() //nolint:errcheck
	if !r.registered.Load() {
		t.Fatal("Dial returned before the relay registered the agent")
	}

	_, err = Dial(ctx, serveRelay(t, &registeringRelay{refuse: true}), WithAgentID("x"), WithAPIKey("k"), WithTLS(false))
	if FatalClass(err) != FatalAuth {
		t.Fatalf("refused Dial: err = %v, want FatalAuth", err)
	}
}
