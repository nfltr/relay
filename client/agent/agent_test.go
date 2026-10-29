// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// Config defaults
// ---------------------------------------------------------------------------

func TestApplyDefaults_ZeroValue(t *testing.T) {
	t.Helper()
	cfg := Config{}
	applyDefaults(&cfg)
	if cfg.ServerAddr != "relay:9090" {
		t.Errorf("ServerAddr = %q, want relay:9090", cfg.ServerAddr)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Backend != "http://localhost:8080" {
		t.Errorf("Routes = %v, want default route", cfg.Routes)
	}
	if cfg.Retries != 12 {
		t.Errorf("Retries = %d, want 12", cfg.Retries)
	}
	if cfg.RetryWait != 5 {
		t.Errorf("RetryWait = %d, want 5", cfg.RetryWait)
	}
	if cfg.RequestTimeout != 60 {
		t.Errorf("RequestTimeout = %d, want 60", cfg.RequestTimeout)
	}
	if cfg.Concurrency != 20 {
		t.Errorf("Concurrency = %d, want 20", cfg.Concurrency)
	}
	if cfg.HeartbeatRecvThreshold != 0 || cfg.Liveness != agentwire.LivenessDefault {
		t.Errorf("HeartbeatRecvThreshold = %v, Liveness = %+v; want 0 and the default liveness", cfg.HeartbeatRecvThreshold, cfg.Liveness)
	}
}

func TestHeartbeatRecvThresholdFollowsTheRelay(t *testing.T) {
	stated := map[string][]string{agentwire.HeartbeatKey: {"5000"}}
	for _, tc := range []struct {
		name     string
		cfg      time.Duration
		liveness agentwire.Liveness
		header   map[string][]string
		want     time.Duration
	}{
		{"relay states 5s", 0, agentwire.LivenessDefault, stated, 15 * time.Second},
		{"mobile against a 5s relay", 0, agentwire.LivenessMobile, stated, 50 * time.Second},
		{"older relay", 0, agentwire.LivenessFast, nil, 45 * time.Second},
		{"configured wins", 7 * time.Second, agentwire.LivenessDefault, stated, 7 * time.Second},
		{"off", -1, agentwire.LivenessDefault, stated, 0},
	} {
		if got := heartbeatRecvThreshold(Config{HeartbeatRecvThreshold: tc.cfg, Liveness: tc.liveness}, tc.header); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestApplyDefaults_PreserveExplicit(t *testing.T) {
	t.Helper()
	cfg := Config{
		ServerAddr:     "myserver:9090",
		Retries:        3,
		RetryWait:      2,
		RequestTimeout: 30,
	}
	applyDefaults(&cfg)
	if cfg.ServerAddr != "myserver:9090" {
		t.Errorf("ServerAddr changed to %q", cfg.ServerAddr)
	}
	if cfg.Retries != 3 {
		t.Errorf("Retries changed to %d", cfg.Retries)
	}
}

// ---------------------------------------------------------------------------
// Route parsing
// ---------------------------------------------------------------------------

func TestParseRoutes_Default(t *testing.T) {
	t.Helper()
	rt, err := parseRoutes([]Route{{Backend: "http://localhost:8080"}})
	if err != nil {
		t.Fatalf("parseRoutes: %v", err)
	}
	u := rt[""]
	if u == nil || u.Host != "localhost:8080" {
		t.Errorf("default route = %v", u)
	}
}

func TestParseRoutes_Multi(t *testing.T) {
	t.Helper()
	rt, err := parseRoutes([]Route{
		{Backend: "http://localhost:8080"},
		{Prefix: "api", Backend: "http://localhost:3001"},
	})
	if err != nil {
		t.Fatalf("parseRoutes: %v", err)
	}
	if rt[""] == nil {
		t.Error("missing default route")
	}
	if rt["api"] == nil || rt["api"].Host != "localhost:3001" {
		t.Errorf("api route = %v", rt["api"])
	}
}

func TestParseRoutes_EmptyBackend(t *testing.T) {
	t.Helper()
	_, err := parseRoutes([]Route{{Prefix: "api", Backend: ""}})
	if err == nil {
		t.Error("expected error for empty backend")
	}
}

func TestParseRoutes_InvalidScheme(t *testing.T) {
	t.Helper()
	_, err := parseRoutes([]Route{{Backend: "ftp://localhost:21"}})
	if err == nil {
		t.Error("expected error for non-http scheme")
	}
}

// ---------------------------------------------------------------------------
// Route resolution
// ---------------------------------------------------------------------------

func TestRouteTable_Forward_Default(t *testing.T) {
	t.Helper()
	rt, _ := parseRoutes([]Route{{Backend: "http://localhost:8080"}})
	fwd := rt.forward("index.html", nil)
	if fwd.targetBase != "http://localhost:8080" {
		t.Errorf("targetBase = %q", fwd.targetBase)
	}
	if fwd.strippedPath != "index.html" {
		t.Errorf("strippedPath = %q", fwd.strippedPath)
	}
}

func TestRouteTable_Forward_Prefix(t *testing.T) {
	t.Helper()
	rt, _ := parseRoutes([]Route{
		{Backend: "http://localhost:8080"},
		{Prefix: "api", Backend: "http://localhost:3001"},
	})
	fwd := rt.forward("api/users/1", nil)
	if fwd.targetBase != "http://localhost:3001" {
		t.Errorf("targetBase = %q", fwd.targetBase)
	}
	if fwd.strippedPath != "/users/1" {
		t.Errorf("strippedPath = %q", fwd.strippedPath)
	}
	if fwd.prefix != "api" {
		t.Errorf("prefix = %q", fwd.prefix)
	}
}

func TestRouteTable_RouteNames_NonEmpty(t *testing.T) {
	t.Helper()
	rt, _ := parseRoutes([]Route{
		{Backend: "http://localhost:8080"},
		{Prefix: "api", Backend: "http://localhost:3001"},
	})
	names := rt.routeNames()
	if names != "api" {
		t.Errorf("routeNames = %q, want api", names)
	}
}

func TestRouteTable_RouteNames_DefaultOnly(t *testing.T) {
	t.Helper()
	rt, _ := parseRoutes([]Route{{Backend: "http://localhost:8080"}})
	if rt.routeNames() != "" {
		t.Errorf("expected empty routeNames for default-only table")
	}
}

// ---------------------------------------------------------------------------
// splitHostPort
// ---------------------------------------------------------------------------

func TestSplitHostPort_Valid(t *testing.T) {
	t.Helper()
	cases := []struct {
		addr string
		host string
		port int
	}{
		{"rpc.example.com:9090", "rpc.example.com", 9090},
		{"localhost:443", "localhost", 443},
		{"127.0.0.1:8080", "127.0.0.1", 8080},
	}
	for _, c := range cases {
		h, p, err := splitHostPort(c.addr)
		if err != nil {
			t.Errorf("%q: %v", c.addr, err)
			continue
		}
		if h != c.host || p != c.port {
			t.Errorf("%q: got %s:%d, want %s:%d", c.addr, h, p, c.host, c.port)
		}
	}
}

func TestSplitHostPort_Invalid(t *testing.T) {
	t.Helper()
	for _, bad := range []string{"noport", "host:notaport"} {
		_, _, err := splitHostPort(bad)
		if err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// isTextContent / rewriteLocalURLs
// ---------------------------------------------------------------------------

func TestIsTextContent(t *testing.T) {
	t.Helper()
	yes := []string{"text/html", "text/css", "application/javascript", "application/json"}
	no := []string{"image/png", "application/octet-stream", "video/mp4"}
	for _, ct := range yes {
		if !isTextContent(ct) {
			t.Errorf("isTextContent(%q) want true", ct)
		}
	}
	for _, ct := range no {
		if isTextContent(ct) {
			t.Errorf("isTextContent(%q) want false", ct)
		}
	}
}

func TestRewriteLocalURLs_Basic(t *testing.T) {
	t.Helper()
	body := []byte(`<a href="http://localhost:8080/path">click</a>`)
	got := rewriteLocalURLs(body, "http://localhost:8080", "", "")
	if string(got) == string(body) {
		t.Error("expected URL to be rewritten")
	}
}

// ---------------------------------------------------------------------------
// forwardRequest — round-trip against a local httptest.Server
// ---------------------------------------------------------------------------

func TestForwardRequest_OK(t *testing.T) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	msg := newTestProxyRequest("GET", "index.html")
	fwd := resolvedForward{targetBase: backend.URL, strippedPath: "index.html"}

	resp, err := forwardRequest(context.Background(), client, msg, fwd, "test-agent", nil)
	if err != nil {
		t.Fatalf("forwardRequest: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestForwardRequest_404(t *testing.T) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer backend.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	msg := newTestProxyRequest("GET", "missing")
	fwd := resolvedForward{targetBase: backend.URL, strippedPath: "missing"}

	resp, err := forwardRequest(context.Background(), client, msg, fwd, "agent", nil)
	if err != nil {
		t.Fatalf("forwardRequest: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Agent lifecycle
// ---------------------------------------------------------------------------

func TestNew_AgentID(t *testing.T) {
	t.Helper()
	a := New(Config{AgentID: "test-agent-01", APIKey: "key"})
	if a.AgentID() != "test-agent-01" {
		t.Errorf("AgentID = %q", a.AgentID())
	}
}

func TestNew_DoneNotClosedBeforeConnect(t *testing.T) {
	t.Helper()
	a := New(Config{AgentID: "x", APIKey: "k"})
	select {
	case <-a.Done():
		t.Error("Done closed before Connect")
	default:
	}
}

func TestAgent_Close_BeforeConnect(t *testing.T) {
	t.Helper()
	a := New(Config{AgentID: "x", APIKey: "k"})
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Close()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Close blocked for 2s without prior Connect")
	}
}

func TestAgent_Connect_Unreachable(t *testing.T) {
	t.Helper()
	a := New(Config{
		ServerAddr: "localhost:19999", // nothing listening
		AgentID:    "agent-x",
		APIKey:     "key",
		Retries:    2,
		RetryWait:  1, // 1s between retries so test stays fast
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := a.Connect(ctx)
	if err == nil {
		defer a.Close()
		t.Error("expected error connecting to unreachable server")
	}
}

func TestWithLabels_Option(t *testing.T) {
	t.Helper()
	a := New(Config{AgentID: "x", APIKey: "k"},
		WithLabels(map[string]string{"pool": "payments", "region": "us-east"}),
	)
	if a.AgentID() != "x" {
		t.Errorf("AgentID = %q", a.AgentID())
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestProxyRequest(method, reqURL string) *pb.HTTPProxyRequest {
	return &pb.HTTPProxyRequest{
		Request: &pb.HTTPRequest{
			TransactionId: "txn-test",
			Method:        method,
			Url:           reqURL,
			Headers:       map[string]*pb.HeaderValueList{},
		},
		Timestamps: &pb.Timestamps{},
	}
}

// ---------------------------------------------------------------------------
// sendResponse tests
// ---------------------------------------------------------------------------

// stubSendStream captures pb.HTTPProxyResponse messages sent via Send.
type stubSendStream struct {
	sent []*pb.HTTPProxyResponse
}

func (s *stubSendStream) Send(msg *pb.HTTPProxyResponse) error {
	s.sent = append(s.sent, msg)
	return nil
}

func TestSendResponse_EmptyBody_Redirect(t *testing.T) {
	// Redirect responses (302, 301) often have an empty body.
	// sendResponse must still transmit the status code and headers
	// so the proxy server can complete the HTTP response.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/web/index.html", http.StatusFound)
	}))
	defer backend.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	msg := newTestProxyRequest("GET", "")
	fwd := resolvedForward{targetBase: backend.URL, strippedPath: ""}

	resp, err := forwardRequest(context.Background(), client, msg, fwd, "test-agent", nil)
	if err != nil {
		t.Fatalf("forwardRequest: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	stream := &stubSendStream{}
	n, sendErr := sendResponse(context.Background(), stream.Send, resp, msg, fwd, nil)
	if sendErr != nil {
		t.Fatalf("sendResponse: %v", sendErr)
	}
	// Go's http.Redirect writes a small HTML body; the important check
	// is that at least one message was sent so the server doesn't hang.
	_ = n
	if len(stream.sent) == 0 {
		t.Fatal("sendResponse sent zero messages — server would hang waiting for a response")
	}
	got := stream.sent[0]
	if got.Response.StatusCode != int32(http.StatusFound) {
		t.Errorf("status = %d, want %d", got.Response.StatusCode, http.StatusFound)
	}
	loc, ok := got.Response.Headers["Location"]
	if !ok || len(loc.HeaderValues) == 0 {
		t.Fatal("missing Location header in redirect response")
	}
}

func TestSendResponse_EmptyBody_NoContent(t *testing.T) {
	// 204 No Content has no body — must still send a response message.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	msg := newTestProxyRequest("DELETE", "resource/1")
	fwd := resolvedForward{targetBase: backend.URL, strippedPath: "resource/1"}

	resp, err := forwardRequest(context.Background(), client, msg, fwd, "test-agent", nil)
	if err != nil {
		t.Fatalf("forwardRequest: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	stream := &stubSendStream{}
	n, sendErr := sendResponse(context.Background(), stream.Send, resp, msg, fwd, nil)
	if sendErr != nil {
		t.Fatalf("sendResponse: %v", sendErr)
	}
	if n != 0 {
		t.Errorf("bytes = %d, want 0 for 204", n)
	}
	if len(stream.sent) == 0 {
		t.Fatal("sendResponse sent zero messages — server would hang")
	}
	if stream.sent[0].Response.StatusCode != int32(http.StatusNoContent) {
		t.Errorf("status = %d, want %d", stream.sent[0].Response.StatusCode, http.StatusNoContent)
	}
}

func TestSendResponse_EmptyBody_RawRedirect(t *testing.T) {
	// Simulate a redirect with truly zero-length body (no HTML snippet).
	// This is the exact scenario that caused the original bug: Jellyfin
	// returns 302 with only a Location header and no body content.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/web/index.html")
		w.WriteHeader(http.StatusFound)
		// Intentionally write nothing — empty body.
	}))
	defer backend.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	msg := newTestProxyRequest("GET", "")
	fwd := resolvedForward{targetBase: backend.URL, strippedPath: ""}

	resp, err := forwardRequest(context.Background(), client, msg, fwd, "test-agent", nil)
	if err != nil {
		t.Fatalf("forwardRequest: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	stream := &stubSendStream{}
	n, sendErr := sendResponse(context.Background(), stream.Send, resp, msg, fwd, nil)
	if sendErr != nil {
		t.Fatalf("sendResponse: %v", sendErr)
	}
	if n != 0 {
		t.Errorf("bytes = %d, want 0 for empty redirect", n)
	}
	if len(stream.sent) == 0 {
		t.Fatal("sendResponse sent zero messages for empty-body redirect — server would hang forever")
	}
	got := stream.sent[0]
	if got.Response.StatusCode != int32(http.StatusFound) {
		t.Errorf("status = %d, want %d", got.Response.StatusCode, http.StatusFound)
	}
	loc, ok := got.Response.Headers["Location"]
	if !ok || len(loc.HeaderValues) == 0 {
		t.Fatal("missing Location header in redirect response")
	}
	if loc.HeaderValues[0] != "/web/index.html" {
		t.Errorf("Location = %q, want %q", loc.HeaderValues[0], "/web/index.html")
	}
}

// ---------------------------------------------------------------------------
// isRetryableError — ensures server-restart errors trigger reconnection
// ---------------------------------------------------------------------------

func TestIsRetryableError(t *testing.T) {
	t.Helper()
	cases := []struct {
		name      string
		err       error
		retryable bool
	}{
		{"Unavailable", status.Error(codes.Unavailable, "server shutting down"), true},
		{"Internal", status.Error(codes.Internal, "internal"), true},
		{"Aborted", status.Error(codes.Aborted, "aborted"), true},
		{"ResourceExhausted", status.Error(codes.ResourceExhausted, "throttled"), true},
		{"Canceled", status.Error(codes.Canceled, "canceled"), true},
		{"Unauthenticated", status.Error(codes.Unauthenticated, "bad key"), false},
		{"PermissionDenied", status.Error(codes.PermissionDenied, "denied"), false},
		{"AlreadyExists (G-R1)", status.Error(codes.AlreadyExists, "Agent for AgentID acct.web is already connected"), true},
		{"session replaced", status.Error(codes.FailedPrecondition, "this session was replaced by a newer one with the same agent ID and key"), false},
		{"InvalidArgument", status.Error(codes.InvalidArgument, "bad arg"), false},
		{"EOF string", fmt.Errorf("stream: %w", fmt.Errorf("EOF")), true},
		{"connection reset", fmt.Errorf("read: connection reset by peer"), true},
		{"connection refused", fmt.Errorf("dial: connection refused"), true},
		{"transport closing", fmt.Errorf("transport is closing"), true},
		{"goaway graceful_stop", fmt.Errorf("rpc error: code = Unavailable desc = closing transport due to: connection error: desc = \"error reading from server: EOF\", received prior goaway: code: NO_ERROR, debug data: \"graceful_stop\""), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isRetryableError(c.err)
			if got != c.retryable {
				t.Errorf("isRetryableError(%v) = %v, want %v", c.err, got, c.retryable)
			}
		})
	}
}

// TestIsHeartbeat_NilSafe locks down the contract that the receive loop
// in processStream relies on: isHeartbeat must return true (and therefore
// not panic) when either the envelope or its Request field is nil.
// A nil-Request frame slipping through caused a SIGSEGV at run.go:114
// (addr=0x30 = Payload field offset on a nil *HTTPRequest).
func TestIsHeartbeat_NilSafe(t *testing.T) {
	cases := []struct {
		name string
		msg  *pb.HTTPProxyRequest
		want bool
	}{
		{"nil envelope", nil, true},
		{"empty envelope", &pb.HTTPProxyRequest{}, true},
		{"nil request, timestamps set", &pb.HTTPProxyRequest{Timestamps: &pb.Timestamps{RequestAtHttpServer: 1}}, true},
		{"request with empty txn", &pb.HTTPProxyRequest{Request: &pb.HTTPRequest{Url: "x"}}, true},
		{"request with txn", &pb.HTTPProxyRequest{Request: &pb.HTTPRequest{TransactionId: "t"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isHeartbeat(c.msg)
			if got != c.want {
				t.Errorf("isHeartbeat = %v, want %v", got, c.want)
			}
		})
	}
}

type cycleTestCloser struct {
	once   sync.Once
	closed chan struct{}
}

func newCycleTestCloser() *cycleTestCloser {
	return &cycleTestCloser{closed: make(chan struct{})}
}

func (c *cycleTestCloser) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}

func TestSuperviseConnectionCycle_AuxiliaryErrorClosesPrimary(t *testing.T) {
	ctx := t.Context()

	closer := newCycleTestCloser()
	primaryExited := make(chan struct{})

	err := superviseConnectionCycle(
		ctx,
		closer,
		func() error {
			<-closer.closed
			close(primaryExited)
			return fmt.Errorf("recv: EOF")
		},
		func() error {
			return fmt.Errorf("tcp tunnel: %w", status.Error(codes.Unavailable, "received prior goaway: graceful_stop"))
		},
	)

	if err == nil {
		t.Fatal("expected error")
	}
	if !isRetryableError(err) {
		t.Fatalf("expected retryable error, got %v", err)
	}
	select {
	case <-primaryExited:
	case <-time.After(time.Second):
		t.Fatal("primary loop did not exit after auxiliary failure")
	}
}

// ---------------------------------------------------------------------------
// processStream concurrency
// ---------------------------------------------------------------------------

// mockStream is a simple in-memory implementation of pb.Dispatcher_ConnectHTTPClient
// that feeds a fixed set of requests and captures all Send calls.
type mockStream struct {
	requests []*pb.HTTPProxyRequest
	idx      int
	mu       sync.Mutex
	sent     []*pb.HTTPProxyResponse
}

func (m *mockStream) Recv() (*pb.HTTPProxyRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.requests) {
		// Return a stream-closed error after all requests have been served.
		return nil, fmt.Errorf("EOF")
	}
	req := m.requests[m.idx]
	m.idx++
	return req, nil
}

func (m *mockStream) Send(msg *pb.HTTPProxyResponse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

func (m *mockStream) CloseSend() error             { return nil }
func (m *mockStream) Header() (metadata.MD, error) { return nil, nil }
func (m *mockStream) Trailer() metadata.MD         { return nil }
func (m *mockStream) Context() context.Context     { return context.Background() }
func (m *mockStream) SendMsg(_ any) error          { return nil }
func (m *mockStream) RecvMsg(_ any) error          { return nil }

type blockingStream struct {
	ctx      context.Context
	requests chan *pb.HTTPProxyRequest
	sent     chan *pb.HTTPProxyResponse
	header   metadata.MD
}

func (s *blockingStream) Recv() (*pb.HTTPProxyRequest, error) {
	select {
	case req := <-s.requests:
		return req, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *blockingStream) Send(msg *pb.HTTPProxyResponse) error {
	select {
	case s.sent <- msg:
	default:
	}
	return nil
}

func (s *blockingStream) CloseSend() error             { return nil }
func (s *blockingStream) Header() (metadata.MD, error) { return s.header, nil }
func (s *blockingStream) Trailer() metadata.MD         { return nil }
func (s *blockingStream) Context() context.Context     { return s.ctx }
func (s *blockingStream) SendMsg(_ any) error          { return nil }
func (s *blockingStream) RecvMsg(_ any) error          { return nil }

func TestRecvHTTPProxyRequestWithActivityTimeout_ResetsOnDataMessage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stream := &blockingStream{
			ctx:      ctx,
			requests: make(chan *pb.HTTPProxyRequest, 1),
			sent:     make(chan *pb.HTTPProxyResponse, 1),
		}

		go func() {
			time.Sleep(10 * time.Millisecond)
			stream.requests <- &pb.HTTPProxyRequest{Request: &pb.HTTPRequest{TransactionId: "txn-activity"}}
		}()

		start := time.Now()
		msg, err := recvHTTPProxyRequestWithActivityTimeout(ctx, stream, 25*time.Millisecond)
		if err != nil {
			t.Fatalf("first receive returned error: %v", err)
		}
		if msg.GetRequest().GetTransactionId() != "txn-activity" {
			t.Fatalf("transaction id = %q, want txn-activity", msg.GetRequest().GetTransactionId())
		}

		_, err = recvHTTPProxyRequestWithActivityTimeout(ctx, stream, 25*time.Millisecond)
		if !errors.Is(err, errNoServerActivity) {
			t.Fatalf("second receive error = %v, want errNoServerActivity", err)
		}
		if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
			t.Fatalf("activity did not reset timeout; elapsed=%v", elapsed)
		}

		cancel()
		synctest.Wait()
	})
}

func TestProcessStream_ServerSilenceTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stream := &blockingStream{
			ctx:      ctx,
			requests: make(chan *pb.HTTPProxyRequest),
			sent:     make(chan *pb.HTTPProxyResponse, 1),
		}
		cfg := Config{
			RequestTimeout:         5,
			Concurrency:            1,
			HeartbeatRecvThreshold: 20 * time.Millisecond,
		}
		routes, err := parseRoutes([]Route{{Backend: "http://127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}

		err = processStream(ctx, stream, "test-agent", routes, cfg, newBackendClient(cfg), slog.Default(), nil, nil, nil)
		if !errors.Is(err, errNoServerActivity) {
			t.Fatalf("processStream error = %v, want errNoServerActivity", err)
		}

		cancel()
		synctest.Wait()
	})
}

// A relay that states its heartbeat sets the silence limit: three intervals
// without any frame end the stream, with no limit configured.
func TestProcessStream_SilenceLimitFromRelayHeartbeat(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stream := &blockingStream{ctx: ctx, requests: make(chan *pb.HTTPProxyRequest), sent: make(chan *pb.HTTPProxyResponse, 1),
			header: metadata.Pairs(agentwire.HeartbeatPairs(agentwire.HeartbeatKey, time.Second)...)}
		routes, err := parseRoutes([]Route{{Backend: "http://127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		err = processStream(ctx, stream, "test-agent", routes, Config{RequestTimeout: 5, Concurrency: 1}, newBackendClient(Config{RequestTimeout: 5, Concurrency: 1}), slog.Default(), nil, nil, nil)
		if !errors.Is(err, errNoServerActivity) || time.Since(start) != 3*time.Second {
			t.Fatalf("processStream = %v after %s, want errNoServerActivity after 3s", err, time.Since(start))
		}
		cancel()
		synctest.Wait()
	})
}

func TestProcessStream_ConcurrentRequests(t *testing.T) {
	t.Helper()

	const numRequests = 10

	// Start a slow local backend that adds a small delay so all requests
	// overlap in flight — verifying that processStream handles them concurrently.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	routes, err := parseRoutes([]Route{{Backend: backend.URL}})
	if err != nil {
		t.Fatalf("parseRoutes: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	requests := make([]*pb.HTTPProxyRequest, numRequests)
	for i := range requests {
		requests[i] = newTestProxyRequest("GET", fmt.Sprintf("req-%d", i))
	}

	stream := &mockStream{requests: requests}

	cfg := Config{
		RequestTimeout: 5,
		Concurrency:    numRequests, // allow all requests in parallel
	}

	start := time.Now()
	processStream(ctx, stream, "test-agent", routes, cfg, newBackendClient(cfg), slog.Default(), nil, nil, nil) //nolint:errcheck // context cancel is expected

	elapsed := time.Since(start)

	stream.mu.Lock()
	got := len(stream.sent)
	stream.mu.Unlock()

	if got != numRequests {
		t.Errorf("sent %d responses, want %d", got, numRequests)
	}

	// Verify all responses carry StatusOK.
	for i, r := range stream.sent {
		if r.Response == nil {
			t.Errorf("response[%d]: nil Response", i)
			continue
		}
		if r.Response.StatusCode != int32(http.StatusOK) {
			t.Errorf("response[%d]: status = %d, want %d", i, r.Response.StatusCode, http.StatusOK)
		}
	}

	// With concurrency=10 and 20ms delay per request, total elapsed should be
	// much less than the sequential bound of 10*20ms = 200ms.
	if elapsed > 150*time.Millisecond {
		t.Errorf("processStream took %v — expected concurrent execution (~20ms), got sequential-like timing", elapsed)
	}
}
