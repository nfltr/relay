// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// moveRelay hands each ConnectHTTP stream to the test.
type moveRelay struct {
	pb.UnimplementedDispatcherServer
	streams chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest]
	refuse  atomic.Bool  // refuse every further stream
	refuseN atomic.Int32 // refuse this many further streams
	// ends, when set, gets each stream's end: closing it ends the stream,
	// as the relay ends one the agent moved off.
	ends   chan chan struct{}
	endErr error // what a stream ended through ends returns
	// stall: further streams get no headers until the agent gives up
	// on them; each one given up is sent on stalled.
	stall   atomic.Bool
	stalled chan struct{}
	// closed, when set, gets one event per relay-side connection closed.
	closed chan struct{}
}

func (f *moveRelay) ConnectHTTP(stream grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest]) error {
	if f.refuse.Load() || f.refuseN.Add(-1) >= 0 {
		return status.Error(codes.Unavailable, "no replica")
	}
	if f.stall.Load() {
		<-stream.Context().Done()
		f.stalled <- struct{}{}
		return nil
	}
	_ = stream.SendHeader(metadata.Pairs(append(agentwire.WelcomePairs("v-test"), "x-resolved-agent-id", "resolved")...))
	f.streams <- stream
	if f.ends != nil {
		end := make(chan struct{})
		f.ends <- end
		select {
		case <-stream.Context().Done():
		case <-end:
		}
		return f.endErr
	}
	<-stream.Context().Done()
	return nil
}

func recvNonHeartbeat(t *testing.T, s grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest]) (*pb.HTTPProxyResponse, error) {
	t.Helper()
	for {
		m, err := s.Recv()
		if err != nil || m.GetResponse() != nil || m.GetMove() != pb.Move_MOVE_UNSPECIFIED {
			return m, err
		}
	}
}

// TestAgentMovesMakeBeforeBreak: on MOVE_RECONNECT the agent opens a new
// stream before it tells the old one MOVE_CONNECTED; a request the relay
// sent on the old stream before MOVE_DONE is answered there, and only then
// does the agent close the old stream, without redialling again.
func TestAgentMovesMakeBeforeBreak(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond) // in flight across MOVE_DONE
		_, _ = io.WriteString(w, "answered")
	}))
	defer backend.Close()
	f := &moveRelay{streams: make(chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest], 4)}
	addr, stop := startMoveRelay(t, f)
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := New(Config{ServerAddr: addr, AgentID: "mover", Retries: 3, Logger: slog.New(slog.DiscardHandler), Routes: []Route{{Backend: backend.URL}}})
	if err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	old := nextStream(t, f, "first connection")
	if md, _ := metadata.FromIncomingContext(old.Context()); len(md.Get(agentwire.MoveKey)) == 0 || md.Get(agentwire.MoveKey)[0] != "1" {
		t.Fatalf("agent did not advertise %s: %v", agentwire.MoveKey, md)
	}

	if err := old.Send(&pb.HTTPProxyRequest{Move: pb.Move_MOVE_RECONNECT}); err != nil {
		t.Fatal(err)
	}
	newStream := nextStream(t, f, "new connection")
	m, err := recvNonHeartbeat(t, old)
	if err != nil || m.GetMove() != pb.Move_MOVE_CONNECTED {
		t.Fatalf("old stream: got %v %v, want MOVE_CONNECTED after the new stream opened", m, err)
	}
	// A request already routed to the old stream, then MOVE_DONE.
	if err := old.Send(newTestProxyRequest(http.MethodGet, "/x")); err != nil {
		t.Fatal(err)
	}
	if err := old.Send(&pb.HTTPProxyRequest{Move: pb.Move_MOVE_DONE}); err != nil {
		t.Fatal(err)
	}
	m, err = recvNonHeartbeat(t, old)
	if err != nil || string(m.GetResponse().GetPayload()) != "answered" {
		t.Fatalf("in-flight request on the old stream: got %v %v, want its answer", m, err)
	}
	if m, err := recvNonHeartbeat(t, old); err != io.EOF {
		t.Fatalf("old stream after its last answer: got %v %v, want the agent to close it (EOF)", m, err)
	}
	select {
	case <-f.streams:
		t.Fatal("agent redialled after the move")
	case <-time.After(500 * time.Millisecond):
	}
	// The new stream serves.
	if err := newStream.Send(newTestProxyRequest(http.MethodGet, "/y")); err != nil {
		t.Fatal(err)
	}
	if m, err := recvNonHeartbeat(t, newStream); err != nil || string(m.GetResponse().GetPayload()) != "answered" {
		t.Fatalf("new stream: got %v %v", m, err)
	}
	if r := a.Stats().Reconnects; r.Move != 1 || r.Lost+r.Drain != 0 {
		t.Fatalf("reconnects %+v, want one move", r)
	}
}

// TestAgentStaysWhenMoveFails: when the new connection cannot be made the
// agent keeps serving the old stream (until the relay lets it go).
func TestAgentStaysWhenMoveFails(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "answered") }))
	defer backend.Close()
	f := &moveRelay{streams: make(chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest], 4)}
	addr, stop := startMoveRelay(t, f)
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := New(Config{ServerAddr: addr, AgentID: "stayer", Retries: 1, Logger: slog.New(slog.DiscardHandler), Routes: []Route{{Backend: backend.URL}}})
	if err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	old := nextStream(t, f, "first connection")
	f.refuse.Store(true) // every further connect fails
	if err := old.Send(&pb.HTTPProxyRequest{Move: pb.Move_MOVE_RECONNECT}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := old.Send(newTestProxyRequest(http.MethodGet, "/x")); err != nil {
		t.Fatal(err)
	}
	if m, err := recvNonHeartbeat(t, old); err != nil || string(m.GetResponse().GetPayload()) != "answered" {
		t.Fatalf("old stream after a failed move: got %v %v, want it still served", m, err)
	}
}

// TestAgentMoveRetriesRefusedConnections: a move's new connection that a
// replica refuses (it landed on the replica moving it, or on another one
// above the fleet's mean, which refuse new agents) is tried again, so the
// agent still moves make-before-break: one MOVE_CONNECTED, after the
// refusals.
func TestAgentMoveRetriesRefusedConnections(t *testing.T) {
	f := &moveRelay{streams: make(chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest], 4)}
	addr, stop := startMoveRelay(t, f)
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := New(Config{ServerAddr: addr, AgentID: "mover", Retries: 3, Logger: slog.New(slog.DiscardHandler)})
	// The retries, not the move's window (moveRetryFor, which a starved
	// machine's three attempts can outlast) are what this checks.
	a.(*agent).moveRetryFor = time.Minute
	if err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	old := nextStream(t, f, "first connection")
	f.refuseN.Store(3)
	if err := old.Send(&pb.HTTPProxyRequest{Move: pb.Move_MOVE_RECONNECT}); err != nil {
		t.Fatal(err)
	}
	nextStream(t, f, "new connection after three refusals")
	if m, err := recvNonHeartbeat(t, old); err != nil || m.GetMove() != pb.Move_MOVE_CONNECTED {
		t.Fatalf("old stream: got %v %v, want MOVE_CONNECTED", m, err)
	}
}

func startMoveRelay(t *testing.T, f *moveRelay) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDispatcherServer(srv, f)
	if f.closed != nil {
		ln = closeWatchListener{ln, f.closed}
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), srv.Stop
}

func nextStream(t *testing.T, f *moveRelay, what string) grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest] {
	t.Helper()
	select {
	case s := <-f.streams:
		return s
	case <-time.After(30 * time.Second): // a hang: a starved machine takes seconds
		t.Fatalf("%s: no stream within 30 s", what)
		return nil
	}
}

// TestReplacedConnectionWaitsForItsTCPSessions: a connection another process
// took over (a rolling update's new pod: same agent ID and key) stays open
// until the TCP sessions it carries ended, as a connection the agent moved
// off does; other ends close it at once. The relay-side guard is
// nfltr-relay's TestTakeoverLetsOpenSessionsFinish.
func TestReplacedConnectionWaitsForItsTCPSessions(t *testing.T) {
	replaced := status.Error(codes.FailedPrecondition, "this session was replaced by a newer one with the same agent ID and key")
	for err, want := range map[error]bool{
		errMoved:                                true,
		fmt.Errorf("recv: %w", replaced):        true,
		status.Error(codes.Unavailable, "gone"): false,
		io.EOF:                                  false,
	} {
		if got := waitsForTCPSessions(err); got != want {
			t.Errorf("waitsForTCPSessions(%v) = %v, want %v", err, got, want)
		}
	}
	g := &tcpStreamGrowth{}
	g.active.Store(1)
	done := make(chan struct{})
	go func() { g.waitIdle(t.Context()); close(done) }()
	select {
	case <-done:
		t.Fatal("waitIdle returned while a session was open")
	case <-time.After(moveTCPQuiet + 200*time.Millisecond):
	}
	g.active.Store(0)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waitIdle did not return once the last session ended")
	}
}

// TestDrainContexts: with a drain, a stop (ctx ending) leaves the TCP
// tunnel's contexts and the cycle's running, with their values, until the
// cycle ends; without one they are ctx and streamCtx. End to end (nfltr up
// SIGTERM: the open session runs to its end, the agent leaves the relay at
// once): nfltr connect conformance TestAgentDrain.
func TestDrainContexts(t *testing.T) {
	type key struct{}
	ctx, stop := context.WithCancel(context.Background())
	streamCtx := context.WithValue(ctx, key{}, "md")
	tcpCtx, tcpStreamCtx, cycleCtx, end := drainContexts(ctx, streamCtx, time.Second)
	stop()
	if tcpCtx.Err() != nil || tcpStreamCtx.Err() != nil || cycleCtx.Err() != nil {
		t.Fatal("a stop ended the drain's contexts")
	}
	if tcpStreamCtx.Value(key{}) != "md" {
		t.Fatal("the TCP stream's context lost the stream's values")
	}
	end()
	if tcpCtx.Err() == nil || tcpStreamCtx.Err() == nil {
		t.Fatal("end left the drain's contexts running")
	}
	ctx2, stop2 := context.WithCancel(context.Background())
	if c, s, cy, _ := drainContexts(ctx2, ctx2, 0); c != ctx2 || s != ctx2 || cy != ctx2 {
		t.Fatal("no drain: want ctx and streamCtx as they are")
	}
	stop2()
}

type closeWatchListener struct {
	net.Listener
	closed chan struct{}
}

func (l closeWatchListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &closeWatchConn{Conn: c, closed: l.closed}, nil
}

type closeWatchConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeWatchConn) Close() error {
	c.once.Do(func() { c.closed <- struct{}{} })
	return c.Conn.Close()
}

// TestMoveGivesUpAStalledConnection: a move's new connection that the
// relay neither accepts nor refuses (a dial through a stalled path) is
// given up within moveRetryFor, as the relay gives up the move, and the
// agent keeps serving the old stream. Before: moveConnect waited on it for
// the agent's lifetime.
func TestMoveGivesUpAStalledConnection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "answered") }))
	defer backend.Close()
	f := &moveRelay{streams: make(chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest], 4), stalled: make(chan struct{}, 4)}
	addr, stop := startMoveRelay(t, f)
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := New(Config{ServerAddr: addr, AgentID: "mover", Retries: 3, Logger: slog.New(slog.DiscardHandler), Routes: []Route{{Backend: backend.URL}}})
	a.(*agent).moveRetryFor = 500 * time.Millisecond
	if err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	old := nextStream(t, f, "first connection")
	f.stall.Store(true)
	if err := old.Send(&pb.HTTPProxyRequest{Move: pb.Move_MOVE_RECONNECT}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.stalled:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled move connection was not given up within 5 s (moveRetryFor 500 ms)")
	}
	if err := old.Send(newTestProxyRequest(http.MethodGet, "/x")); err != nil {
		t.Fatal(err)
	}
	if m, err := recvNonHeartbeat(t, old); err != nil || string(m.GetResponse().GetPayload()) != "answered" {
		t.Fatalf("old stream after a given-up move: got %v %v, want it still served", m, err)
	}
}

// TestRelayLetGoConnectsBeforeClosing: a connection the relay lets go
// without a move (a leaving replica that gave up moving the agent ends
// ConnectHTTP Canceled; a graceful stop) is not closed at once, which cut
// its TCP sessions: the agent connects again first and closes the old
// connection once its TCP sessions ended (waitIdle), as after a move.
func TestRelayLetGoConnectsBeforeClosing(t *testing.T) {
	f := &moveRelay{
		streams: make(chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest], 4),
		ends:    make(chan chan struct{}, 4),
		endErr:  status.Error(codes.Canceled, "Canceled"), // the relay's errServerRestarting on ConnectHTTP
		closed:  make(chan struct{}, 4),
	}
	addr, stop := startMoveRelay(t, f)
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := New(Config{ServerAddr: addr, AgentID: "let-go", Retries: 3, Logger: slog.New(slog.DiscardHandler)})
	if err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	nextStream(t, f, "first connection")
	close(<-f.ends)
	nextStream(t, f, "new connection")
	select {
	case <-f.closed:
		t.Fatal("the old connection closed before the agent connected again")
	default:
	}
	select {
	case <-f.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the old connection was not closed once it carried no TCP session")
	}
	for err, want := range map[error]bool{
		nil:                                      true,
		io.EOF:                                   true,
		status.Error(codes.Canceled, "x"):        true,
		status.Error(codes.Unauthenticated, "x"): false,
	} {
		if got := relayLetGo(err); got != want {
			t.Errorf("relayLetGo(%v) = %v, want %v", err, got, want)
		}
	}
}

// TestAgentStaysConnectedAcrossAMove: Connected is true while the agent
// holds an accepted connection, also after the relay ended the old one of a
// make-before-break move (the new one was accepted first), and false once
// the agent stopped. A flag set by each WithConnected call and cleared by
// its Done read false here: the old connection's Done closes last.
func TestAgentStaysConnectedAcrossAMove(t *testing.T) {
	f := &moveRelay{
		streams: make(chan grpc.BidiStreamingServer[pb.HTTPProxyResponse, pb.HTTPProxyRequest], 4),
		ends:    make(chan chan struct{}, 4),
		endErr:  status.Error(codes.Unavailable, "server restarting"),
	}
	addr, stop := startMoveRelay(t, f)
	defer stop()
	dones := make(chan (<-chan struct{}), 4)
	a := New(Config{ServerAddr: addr, AgentID: "mover", Retries: 3, Logger: slog.New(slog.DiscardHandler)},
		WithConnected(func(c Connection) (*Tunnel, error) { dones <- c.Done; return nil, nil }))
	if a.Connected() {
		t.Fatal("Connected before Connect")
	}
	if err := a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !a.Connected() {
		t.Fatal("not Connected after Connect")
	}
	old, oldEnd, oldDone := nextStream(t, f, "first connection"), <-f.ends, <-dones
	if err := old.Send(&pb.HTTPProxyRequest{Move: pb.Move_MOVE_RECONNECT}); err != nil {
		t.Fatal(err)
	}
	nextStream(t, f, "new connection")
	if m, err := recvNonHeartbeat(t, old); err != nil || m.GetMove() != pb.Move_MOVE_CONNECTED {
		t.Fatalf("old stream: got %v %v, want MOVE_CONNECTED", m, err)
	}
	close(oldEnd) // the old relay ends the stream, as a restarting one does
	select {
	case <-oldDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the old connection did not end")
	}
	if !a.Connected() {
		t.Fatal("not Connected after the old connection of a move ended")
	}
	a.Close()
	if a.Connected() {
		t.Fatal("Connected after Close")
	}
}
