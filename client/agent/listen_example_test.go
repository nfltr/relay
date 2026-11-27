// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"testing"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// exampleRelay stands in for a relay: it sends the agent one visitor
// request and hands back the first response.
type exampleRelay struct {
	pb.UnimplementedDispatcherServer
	resp chan *pb.HTTPResponse
}

func (r *exampleRelay) ConnectHTTP(stream grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest]) error {
	_ = stream.SendHeader(metadata.Pairs(append(agentwire.WelcomePairs("example"), "x-resolved-agent-id", "my-app")...))
	req := newTestProxyRequest(http.MethodGet, "hello")
	if err := stream.Send(req); err != nil {
		return err
	}
	for {
		m, err := stream.Recv()
		if err != nil {
			return err
		}
		if m.GetResponse().GetTransactionId() == req.Request.TransactionId {
			r.resp <- m.GetResponse()
			<-stream.Context().Done()
			return nil
		}
	}
}

func exampleRelayAddr(r *exampleRelay) (addr string, stop func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDispatcherServer(srv, r)
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), srv.Stop
}

// Serve an http.Handler through the relay.
func ExampleListen() {
	relay := &exampleRelay{resp: make(chan *pb.HTTPResponse, 1)}
	addr, stop := exampleRelayAddr(relay) // a real relay: "rpc.example.com:443" with TLS: true
	defer stop()

	ln, err := Listen(context.Background(), Config{
		ServerAddr: addr, AgentID: "my-app", Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { //nolint:gosec // example
		fmt.Fprintf(w, "hello from %s", r.URL.Path)
	})}
	defer srv.Close() //nolint:errcheck // also closes ln, which stops the agent
	go srv.Serve(ln)  //nolint:errcheck

	resp := <-relay.resp
	fmt.Println(resp.StatusCode, string(resp.Payload))
	// Output: 200 hello from /hello
}

// Listen's listener is the agent's only backend.
func TestListenRefusesRoutes(t *testing.T) {
	_, err := Listen(context.Background(), Config{AgentID: "a", Routes: []Route{{Backend: "http://127.0.0.1:1"}}})
	if err == nil {
		t.Fatal("Listen took cfg.Routes")
	}
}
