// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpcmd "google.golang.org/grpc/metadata"
)

// instanceRecorder records the instance header of each AgentTunnel.
type instanceRecorder struct {
	pb.UnimplementedDispatcherServer
	got chan string
}

func (r *instanceRecorder) AgentTunnel(s grpc.BidiStreamingServer[pb.TunnelFrame, pb.TunnelFrame]) error {
	md, _ := grpcmd.FromIncomingContext(s.Context())
	v := ""
	if vals := md.Get(InstanceHeader); len(vals) > 0 {
		v = vals[0]
	}
	_ = s.SendHeader(grpcmd.MD{}) // the relay's accept
	r.got <- v
	<-s.Context().Done()
	return nil
}

// Every Dial of one process sends the same instance id, so the relay tells
// this process's reconnect from another process taking its agent id.
func TestDialSendsTheProcessInstanceID(t *testing.T) {
	rec := &instanceRecorder{got: make(chan string, 2)}
	srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	pb.RegisterDispatcherServer(srv, rec)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var ids []string
	for range 2 {
		a, err := Dial(ctx, lis.Addr().String(), WithAgentID("node-x"), WithAPIKey("k"), WithTLS(false))
		if err != nil {
			t.Fatal(err)
		}
		select {
		case id := <-rec.got:
			ids = append(ids, id)
		case <-ctx.Done():
			t.Fatal("no AgentTunnel reached the server")
		}
		_ = a.Close()
	}
	if ids[0] == "" || ids[0] != ids[1] || ids[0] != processInstanceID {
		t.Fatalf("instance ids = %q, want this process's on every dial", ids)
	}
}
