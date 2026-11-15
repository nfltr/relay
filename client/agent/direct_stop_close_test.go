// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/nfltr/link/pathswitch"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc"
)

// tunnelRelay is a moveRelay that also holds each ConnectTCP stream open.
type tunnelRelay struct{ *moveRelay }

func (f tunnelRelay) ConnectTCP(s grpc.BidiStreamingServer[pb.TCPData, pb.TCPData]) error {
	<-s.Context().Done()
	return nil
}

// TestStopResetsDirectSessionsBeforeClose (lane UDPFIX, nfltr NAT lab
// nf1-udp-revoke-TERM): an agent without a drain returns from its stop at
// once, so its process may exit right after Close; a session on a direct
// path (a udp association's, its datagrams on QUIC datagrams) must have
// been reset by then, or its client never hears of the stop and lives on
// until its detach bound. Close returns only after the stop reset every
// direct session and its peer answered.
func TestStopResetsDirectSessionsBeforeClose(t *testing.T) {
	for i := range 10 {
		lis, _, err := nf1.Mint("relay.example")
		if err != nil {
			t.Fatal(err)
		}
		table := nf1Table(t, lis, echoTarget(t), DirectOn)
		f := tunnelRelay{&moveRelay{streams: make(chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest], 4)}}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := grpc.NewServer()
		pb.RegisterDispatcherServer(srv, f)
		go func() { _ = srv.Serve(ln) }()
		a := New(Config{ServerAddr: ln.Addr().String(), AgentID: "web", Retries: 3, Logger: slog.New(slog.DiscardHandler)},
			WithConnected(func(Connection) (*Tunnel, error) { return &Tunnel{Services: table}, nil }))
		if err := a.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		nextStream(t, f.moveRelay, "connection")

		sc, cc := net.Pipe()
		cfg := pathswitch.Config{Detach: time.Minute}
		s := pathswitch.Server(pathStream{Conn: sc}, PathRelayed, cfg)
		c := pathswitch.Client(pathStream{Conn: cc}, PathRelayed, cfg)
		table.direct.registerSession(&directSession{c: s})

		a.Close()
		select {
		case <-s.Done():
		default:
			t.Fatalf("run %d: Close returned before the stop reset the direct session", i)
		}
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatalf("run %d: the client's session read on after the stop", i)
		}
		srv.Stop()
	}
}
