// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/nfltr/relay/proto/wire/agentwire"
)

// oneFrame answers every agent stream with one frame, with or without the
// relay's Welcome, and records whether the call carried a Hello.
type oneFrame struct {
	pb.UnimplementedDispatcherServer
	welcome bool
	hello   chan bool // the call carried a Hello and generation 2
}

func (s *oneFrame) AgentTunnel(stream pb.Dispatcher_AgentTunnelServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	_, err := agentwire.ParseHello(md)
	s.hello <- err == nil && agentwire.ParseGeneration(md.Get(agentwire.GenerationKey)) == agentwire.Generation
	if s.welcome {
		_ = stream.SetHeader(metadata.Pairs(agentwire.WelcomePairs("v-test")...))
	}
	if err := stream.Send(&pb.TunnelFrame{}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

// A v1 client sends its Hello on every stream and refuses a relay that
// answers without a Welcome (a pre-v1 relay), with an error naming the fix.
func TestClientIdentitySendsHelloAndRequiresWelcome(t *testing.T) {
	for _, welcome := range []bool{true, false} {
		lis := bufconn.Listen(1 << 20)
		srv := grpc.NewServer()
		impl := &oneFrame{welcome: welcome, hello: make(chan bool, 1)}
		pb.RegisterDispatcherServer(srv, impl)
		go func() { _ = srv.Serve(lis) }()
		conn, err := grpc.NewClient("passthrough://bufnet", append(ClientIdentity(),
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))...)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		stream, err := pb.NewDispatcherClient(conn).AgentTunnel(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = stream.Recv()
		if !<-impl.hello {
			t.Error("the stream carried no Hello or no generation")
		}
		switch {
		case welcome && err != nil:
			t.Errorf("with a Welcome: %v", err)
		case !welcome && (status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != agentwire.RelayTooOld):
			t.Errorf("without a Welcome: %v; want FailedPrecondition %q", err, agentwire.RelayTooOld)
		}
		cancel()
		_ = conn.Close()
		srv.Stop()
	}
}

// TestClientConnsSendGeneration: the connections this package makes for
// callers (NewClientConn; NewMTLSClientConn shares its options) send the
// client generation on every stream, so no caller can omit it.
func TestClientConnsSendGeneration(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	impl := &oneFrame{welcome: true, hello: make(chan bool, 1)}
	pb.RegisterDispatcherServer(srv, impl)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	addr := lis.Addr().(*net.TCPAddr)
	conn, err := NewClientConn(false, "127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := pb.NewDispatcherClient(conn).AgentTunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if !<-impl.hello {
		t.Fatal("NewClientConn's stream carried no Hello or no generation")
	}
}

// A relay that does not serve the service this client calls (a relay from
// before the agent wire's package nfltr.relay.v1) answers gRPC's
// "unknown service": the client names it as a relay too old for it, which
// FatalClass stops on, on unary calls and streams alike. A deliberate
// Unimplemented from a relay that serves the service passes unchanged.
func TestUnknownServiceIsRelayTooOld(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer() // serves nothing: every service is unknown
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough://bufnet", append(ClientIdentity(),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tooOld := func(what string, err error) {
		t.Helper()
		if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != agentwire.RelayTooOld {
			t.Errorf("%s: %v; want FailedPrecondition %q", what, err, agentwire.RelayTooOld)
		}
	}
	stream, err := pb.NewDispatcherClient(conn).AgentTunnel(ctx)
	if err == nil {
		_, err = stream.Recv()
	}
	tooOld("stream", err)
	tooOld("unary", conn.Invoke(ctx, "/nfltr.relay.v1.Absent/Call", &pb.TunnelFrame{}, &pb.TunnelFrame{}))

	if got := relayTooOld(status.Error(codes.Unimplemented, "tcp tunneling is not enabled on this server")); status.Code(got) != codes.Unimplemented {
		t.Errorf("a deliberate Unimplemented became %v", got)
	}
}
