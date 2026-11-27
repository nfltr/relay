// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestBackendTransportOnBothPaths: WithBackendTransport sees every tunnel
// request, on the ConnectHTTP stream and on a link session, with what the
// relay asked (RequestOf), and can answer one itself; the backend sees the
// relay-resolved ID (AgentIDHeader).
func TestBackendTransportOnBothPaths(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "backend "+r.URL.Path+" "+r.Header.Get(AgentIDHeader))
	}))
	defer backend.Close()
	var mu sync.Mutex
	var seen []Request
	wrap := func(next http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			req, ok := RequestOf(r.Context())
			if !ok {
				t.Errorf("no RequestOf for %s", r.URL)
			}
			mu.Lock()
			seen = append(seen, req)
			mu.Unlock()
			if strings.HasSuffix(r.URL.Path, "/deny") {
				return &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("no")), Request: r}, nil
			}
			return next.RoundTrip(r)
		})
	}
	f := &moveRelay{streams: make(chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest], 4)}
	addr, stop := startMoveRelay(t, f)
	defer stop()
	var handler http.Handler
	a := New(Config{ServerAddr: addr, AgentID: "wrapped", Retries: 1, Logger: slog.New(slog.DiscardHandler), Routes: []Route{{Prefix: "app", Backend: backend.URL}}},
		WithBackendTransport(wrap),
		WithConnected(func(c Connection) (*Tunnel, error) { handler = c.HTTP; return nil, nil }))
	if err := a.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	s := nextStream(t, f, "connection")

	// The ConnectHTTP stream.
	for _, c := range []struct{ path, want string }{{"app/x", "backend /x resolved"}, {"app/deny", "no"}} {
		path, want := c.path, c.want
		req := newTestProxyRequest(http.MethodGet, path)
		req.Request.TransactionId = "txn-" + path
		if err := s.Send(req); err != nil {
			t.Fatal(err)
		}
		m, err := recvNonHeartbeat(t, s)
		if err != nil || string(m.GetResponse().GetPayload()) != want {
			t.Fatalf("stream %s: got %v %v, want %q", path, m, err, want)
		}
	}
	// A link session (the handler the agent serves them with).
	srv := httptest.NewServer(handler)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/app/y?q=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "backend /y resolved" {
		t.Fatalf("link session: %q", body)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []Request{{URI: "app/x", TransactionID: "txn-app/x"}, {URI: "app/deny", TransactionID: "txn-app/deny"}, {URI: "app/y?q=1"}}
	if len(seen) != len(want) {
		t.Fatalf("transport saw %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("transport saw %v, want %v", seen, want)
		}
	}
}

// TestServiceRequestHeaderRoutes: a request the relay names a service for
// goes to that route at its root; one that resolves to no backend is
// answered 404, on both paths.
func TestServiceRequestHeaderRoutes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.RequestURI()+" "+r.Header.Get(agentservices.RequestHeader))
	}))
	defer backend.Close()
	routes, err := parseRoutes([]Route{{Prefix: "web", Backend: backend.URL}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		url     string
		service []string
		code    int
		body    string
	}{
		{"index.html", []string{"web"}, 200, "/index.html"}, // the service at its root; the header not forwarded
		{"web/a", nil, 200, "/a"},                           // the owner's browse view
		{"a", []string{"other"}, 404, errNoRoute},
		{"a", nil, 404, errNoRoute},
	}
	// An agent whose services include no http one has no route, not the
	// default backend.
	if rt := New(Config{AgentID: "tcp-only", Routes: []Route{}}).(*agent).routes; len(rt) != 0 {
		t.Fatalf("empty Routes became %v", rt)
	}
	h := newTunnelHandler("svc", routes, newBackendClient(Config{RequestTimeout: 5}), false, slog.New(slog.DiscardHandler))
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/"+c.url, nil)
		for _, v := range c.service {
			r.Header.Add(agentservices.RequestHeader, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.code || strings.TrimSpace(w.Body.String()) != c.body {
			t.Errorf("link %s %v: %d %q, want %d %q", c.url, c.service, w.Code, w.Body.String(), c.code, c.body)
		}
	}
	for _, c := range cases {
		msg := newTestProxyRequest(http.MethodGet, c.url)
		if c.service != nil {
			msg.Request.Headers[agentservices.RequestHeader] = &pb.HeaderValueList{HeaderValues: c.service}
		}
		stream := &mockStream{requests: []*pb.HTTPProxyRequest{msg}}
		cfg := Config{RequestTimeout: 5, Concurrency: 1}
		_ = processStream(context.Background(), stream, "svc", routes, cfg, newBackendClient(cfg), slog.New(slog.DiscardHandler), nil, nil, nil)
		if len(stream.sent) != 1 {
			t.Fatalf("stream %s: %d responses", c.url, len(stream.sent))
		}
		got := stream.sent[0].GetResponse()
		if int(got.GetStatusCode()) != c.code || strings.TrimSpace(string(got.GetPayload())) != c.body {
			t.Errorf("stream %s %v: %d %q, want %d %q", c.url, c.service, got.GetStatusCode(), got.GetPayload(), c.code, c.body)
		}
	}
}

// TestConnectedHook: WithConnected sees each accepted connection (the
// resolved identity, the relay's header, first or not) before it is
// served; the metadata of WithMetadata goes with each; a connection's Done
// closes once the agent moved off it; a hook's error stops the agent.
func TestConnectedHook(t *testing.T) {
	f := &moveRelay{streams: make(chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest], 4), ends: make(chan chan struct{}, 4)}
	addr, stop := startMoveRelay(t, f)
	defer stop()
	conns := make(chan Connection, 4)
	fail := make(chan error, 1)
	fail <- nil
	a := New(Config{ServerAddr: addr, AgentID: "hooked", Retries: 1, Logger: slog.New(slog.DiscardHandler)},
		WithMetadata("x-extra", "1", "x-agent-id", "overridden"),
		WithConnected(func(c Connection) (*Tunnel, error) {
			conns <- c
			return nil, <-fail
		}))
	if err := a.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := <-conns
	old := nextStream(t, f, "first connection")
	endOld := <-f.ends
	md, _ := metadata.FromIncomingContext(old.Context())
	if got := md.Get("x-extra"); len(got) != 1 || got[0] != "1" {
		t.Fatalf("x-extra: %v", got)
	}
	if got := md.Get("x-agent-id"); len(got) != 1 || got[0] != "hooked" {
		t.Fatalf("the agent's own key: %v", got)
	}
	if !first.First || first.AgentID != "resolved" || !agentwire.HasWelcome(first.Header) || first.HTTP == nil {
		t.Fatalf("first connection: %+v", first)
	}

	fail <- nil
	if err := old.Send(&pb.HTTPProxyRequest{Move: pb.Move_MOVE_RECONNECT}); err != nil {
		t.Fatal(err)
	}
	moved := nextStream(t, f, "new connection")
	if second := <-conns; second.First {
		t.Fatal("the move's connection is not the first")
	}
	if m, err := recvNonHeartbeat(t, old); err != nil || m.GetMove() != pb.Move_MOVE_CONNECTED {
		t.Fatalf("old stream: %v %v", m, err)
	}
	if err := old.Send(&pb.HTTPProxyRequest{Move: pb.Move_MOVE_DONE}); err != nil {
		t.Fatal(err)
	}
	if m, err := recvNonHeartbeat(t, old); err != io.EOF {
		t.Fatalf("old stream after MOVE_DONE: %v %v, want the agent to close it", m, err)
	}
	close(endOld) // the relay ends it
	<-f.ends
	select {
	case <-first.Done:
	case <-time.After(5 * time.Second):
		t.Fatal("the first connection's Done did not close after the move")
	}

	// The next connection's hook fails: the agent stops with its error.
	refused := errors.New("refused by the hook")
	fail <- refused
	if err := moved.Send(&pb.HTTPProxyRequest{Move: pb.Move_MOVE_RECONNECT}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the agent did not stop on the hook's error")
	}
	if !errors.Is(a.Err(), refused) {
		t.Fatalf("Err: %v, want the hook's", a.Err())
	}
}

// refusingRelay ends every ConnectHTTP stream before accepting it.
type refusingRelay struct {
	pb.UnimplementedDispatcherServer
	streams int
	mu      sync.Mutex
}

func (f *refusingRelay) ConnectHTTP(grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest]) error {
	f.mu.Lock()
	f.streams++
	f.mu.Unlock()
	return status.Error(codes.FailedPrecondition, "services conflict with the relay's policy")
}

// TestRefusedStreamIsTheConnectError: a relay that ends the stream before
// accepting it says why in its status; Connect returns that status, once,
// without retrying or calling WithConnected.
func TestRefusedStreamIsTheConnectError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &refusingRelay{}
	srv := grpc.NewServer()
	pb.RegisterDispatcherServer(srv, f)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()
	a := New(Config{ServerAddr: ln.Addr().String(), AgentID: "refused", Retries: 3, Logger: slog.New(slog.DiscardHandler)},
		WithConnected(func(Connection) (*Tunnel, error) {
			t.Error("WithConnected called for a refused stream")
			return nil, nil
		}))
	err = a.Connect(t.Context())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "services conflict") {
		t.Fatalf("Connect: %v, want the relay's FailedPrecondition", err)
	}
	if isRetryableError(err) {
		t.Fatal("a refusal is retryable")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.streams != 1 {
		t.Fatalf("%d streams, want 1", f.streams)
	}
}

// TestStreamResponseKeepsContentLength: a response the agent does not
// rewrite keeps its Content-Length on the ConnectHTTP stream, as on a link
// session; a HEAD's is the only length its visitor gets.
func TestStreamResponseKeepsContentLength(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "1234")
		if r.Method != http.MethodHead {
			_, _ = w.Write(make([]byte, 1234))
		}
	}))
	defer backend.Close()
	routes, err := parseRoutes([]Route{{Backend: backend.URL}})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		stream := &mockStream{requests: []*pb.HTTPProxyRequest{newTestProxyRequest(method, "f")}}
		cfg := Config{RequestTimeout: 5, Concurrency: 1}
		_ = processStream(context.Background(), stream, "a", routes, cfg, newBackendClient(cfg), slog.New(slog.DiscardHandler), nil, nil, nil)
		if len(stream.sent) == 0 {
			t.Fatalf("%s: no response", method)
		}
		if got := stream.sent[0].GetResponse().GetHeaders()["Content-Length"].GetHeaderValues(); len(got) != 1 || got[0] != "1234" {
			t.Errorf("%s: Content-Length %v, want 1234", method, got)
		}
	}
}
