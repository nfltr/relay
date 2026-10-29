// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nfltr/relay/client/grpcclient"
	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc"
)

// TestRedialWaitEndsWhenTheRelayIsBack: the wait between two connect
// attempts ends once the connection reaches the relay, however long the
// redial delay: past an outage's first minute that delay grows to
// --retry-wait (and was up to a minute between rounds of attempts), so the
// agent came back that much after its relay.
func TestRedialWaitEndsWhenTheRelayIsBack(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close() // the relay is down

	conn, err := grpcclient.NewClientConn(false, "127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck

	go func() {
		time.Sleep(500 * time.Millisecond)
		ln, err := net.Listen("tcp", addr.String())
		if err != nil {
			return
		}
		srv := grpc.NewServer()
		pb.RegisterDispatcherServer(srv, &fakeRelay{connected: make(chan struct{}, 1)})
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(srv.Stop)
	}()
	start := time.Now()
	waitRedial(context.Background(), conn, 10*time.Second)
	if took := time.Since(start); took > 2500*time.Millisecond {
		t.Fatalf("waited %s for a relay back after 0.5 s; want the wait to end when it is reached", took.Truncate(time.Millisecond))
	}

	// A connection that is up waits the whole delay: the relay refused
	// the attempt, it did not go away.
	start = time.Now()
	waitRedial(context.Background(), conn, 300*time.Millisecond)
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Fatalf("a ready connection waited %s; want the full 300ms", took)
	}
}
