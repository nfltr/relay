// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nfltr/relay/client/grpcclient"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

type servingHealth struct {
	healthpb.UnimplementedHealthServer
}

func (servingHealth) Check(context.Context, *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

// TestClientConnReachesARelayBackFromAnOutageWithinASecond (G-R3): a
// connection that kept failing while the relay was down reaches it within
// about a second of its return. With gRPC's default backoff (1 s growing by
// 1.6x to 120 s) the channel refused every call for the rest of its backoff:
// `wg socks5`, which keeps one connection, came back 17-22 s after a restart.
func TestClientConnReachesARelayBackFromAnOutageWithinASecond(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // the relay is down

	conn, err := grpcclient.NewClientConn(false, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	health := healthpb.NewHealthClient(conn)
	check := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := health.Check(ctx, &healthpb.HealthCheckRequest{})
		return err
	}
	// Six seconds of failed calls: the default backoff would now wait 4 s
	// before its next dial.
	for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if check() == nil {
			t.Fatal("reached a relay that is down")
		}
	}

	ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("port %d taken while the relay was down: %v", port, err)
	}
	srv := grpc.NewServer(v1Relay())
	healthpb.RegisterHealthServer(srv, servingHealth{})
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()
	back := time.Now()
	for check() != nil {
		if time.Since(back) > 2*time.Second {
			t.Fatalf("the relay has been back %s and calls still fail; want it reached within about a second", time.Since(back).Truncate(time.Millisecond))
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("reached %s after the relay came back", time.Since(back).Truncate(time.Millisecond))
}

// TestRedialNowReachesARelayThatIsBack: a caller that paces its own redials
// (pkg/agent, `nfltr http`) reaches a relay that is back on its next
// attempt. Without RedialNow the attempt fell into the channel's own backoff
// (up to 1 s) and failed at once with the last dial's error, so a tunnel came
// back up to a second after the relay (relay-agent-scaling decision, round 3).
func TestRedialNowReachesARelayThatIsBack(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // the relay is down

	conn, err := grpcclient.NewClientConn(false, "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	health := healthpb.NewHealthClient(conn)
	// Failed attempts until the channel's backoff is at its 1 s maximum.
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		_, _ = health.Check(context.Background(), &healthpb.HealthCheckRequest{})
	}

	ln, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("port %d taken while the relay was down: %v", port, err)
	}
	srv := grpc.NewServer(v1Relay())
	healthpb.RegisterHealthServer(srv, servingHealth{})
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()

	grpcclient.RedialNow(context.Background(), conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := health.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("first attempt after RedialNow: %v; want the relay that is back reached", err)
	}
}

// v1Relay makes a test server answer unary calls as a protocol v1 relay
// does (the Welcome header), for tests of grpcclient's connections.
// allow:wrapper
func v1Relay() grpc.ServerOption {
	return grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		_ = grpc.SetHeader(ctx, metadata.Pairs(agentwire.WelcomePairs("v-test")...))
		return h(ctx, req)
	})
}
