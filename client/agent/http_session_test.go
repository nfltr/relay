// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// tunnelBackend answers with what it saw, a Location and a CSP header, and
// an HTML body that links to itself.
func tunnelBackend(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Saw", r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get(AgentIDHeader)+" "+r.Header.Get("X-Forwarded-For")+" "+r.Header.Get("Origin")+" "+string(body))
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Location", srv.URL+"/next")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<a href="`+srv.URL+`/x">x</a>`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestTunnelHandlerForwardsAsTheStreamPathDoes: a request on a link
// session reaches the backend and comes back as processStream relays it
// (routes, agent headers, Origin and X-Forwarded-For as the relay sent
// them, Location, CSP, rewritten links).
func TestTunnelHandlerForwardsAsTheStreamPathDoes(t *testing.T) {
	backend := tunnelBackend(t)
	h, err := NewTunnelHandler(Config{AgentID: "a1", Routes: []Route{{Backend: backend.URL}, {Prefix: "api", Backend: backend.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, saw, location, link string }{
		{"/p?q=1", "POST /p?q=1 a1 203.0.113.7 https://share.example hi", "/next", `href="/x"`},
		{"/api/v1", "POST /v1 a1 203.0.113.7 https://share.example hi", "/api/next", `href="/api/x"`},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader("hi"))
		req.Header.Set("Origin", "https://share.example")
		req.Header.Set("X-Forwarded-For", "203.0.113.7") // the relay's
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("X-Saw"); got != tc.saw {
			t.Errorf("%s: backend saw %q, want %q", tc.path, got, tc.saw)
		}
		if got := rec.Header().Get("Location"); got != tc.location {
			t.Errorf("%s: Location %q, want %q", tc.path, got, tc.location)
		}
		if rec.Header().Get("Content-Security-Policy") != "" || !strings.Contains(rec.Body.String(), tc.link) {
			t.Errorf("%s: CSP %q, body %q", tc.path, rec.Header().Get("Content-Security-Policy"), rec.Body.String())
		}
	}
}

// TestTunnelHandlerUnreachableBackend: 502 with the reason, as the stream
// path answers.
func TestTunnelHandlerUnreachableBackend(t *testing.T) {
	h, err := NewTunnelHandler(Config{AgentID: "a1", Routes: []Route{{Backend: "http://127.0.0.1:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "tunnel forward error") {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

// TestHTTPSessionServedOnTheStream: a session to HTTPSessionTarget is an
// HTTP/1.1 connection the agent serves; a raw target on an HTTP-only
// tunnel is refused, never dialled.
func TestHTTPSessionServedOnTheStream(t *testing.T) {
	backend := tunnelBackend(t)
	h, err := NewTunnelHandler(Config{AgentID: "a1", Routes: []Route{{Backend: backend.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	st := newChanStream(t, 8, 64)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = serveTCPStream(ctx, st, sessionTargets{http: h, noRaw: true}, nil, nil, slog.New(slog.DiscardHandler), nil, nil)
	}()
	st.in <- &pb.TCPData{SessionId: "raw", Open: true, TargetAddr: backend.Listener.Addr().String()}
	st.in <- &pb.TCPData{SessionId: "h1", Open: true, TargetAddr: dataplane.HTTPSessionTarget}
	st.in <- &pb.TCPData{SessionId: "h1", Data: []byte("GET /z HTTP/1.1\r\nHost: agent\r\nConnection: close\r\n\r\n")}
	var resp bytes.Buffer
	rawClosed := false
	deadline := time.After(10 * time.Second)
	for !rawClosed || !strings.Contains(resp.String(), "</a>") {
		select {
		case f := <-st.out:
			switch {
			case f.GetSessionId() == "raw" && f.GetClose():
				rawClosed = true
			case f.GetSessionId() == "raw":
				t.Fatalf("raw session got %v", f)
			case f.GetSessionId() == "h1":
				resp.Write(f.GetData())
			}
		case <-deadline:
			t.Fatalf("raw closed %v, response %q", rawClosed, resp.String())
		}
	}
	r, err := http.ReadResponse(bufio.NewReader(&resp), nil)
	if err != nil || r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("X-Saw"), "GET /z a1") {
		t.Fatalf("response %v %v", r, err)
	}
}

func TestHTTPSessionsValue(t *testing.T) {
	h := http.NotFoundHandler()
	for _, tc := range []struct {
		targets sessionTargets
		want    string
	}{
		{sessionTargets{}, ""},
		{sessionTargets{http: h, noRaw: true}, HTTPSessionsOnly},
		{sessionTargets{http: h}, "1"},
		{sessionTargets{http: h, noRaw: true, services: &ServiceTable{}}, "1"},
	} {
		if got := tc.targets.httpSessionsValue(); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.targets, got, tc.want)
		}
	}
}

// TestNoDataConnectionUntilAnHTTPSession: against a relay that offers data
// connections and no agent link (nfltr-relay v0.15 and older, which never
// opens an HTTP session), an agent that serves HTTP sessions opens no data
// connection while idle; its first HTTP session opens one.
func TestNoDataConnectionUntilAnHTTPSession(t *testing.T) {
	var dials atomic.Int32
	dial := RelayDialer{Data: func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	st := newChanStream(t, 8, 64)
	defer st.closeIn()
	relay := &primaryClient{st: st, md: metadata.Pairs(tcpStreamsHeader, "4", tcpBindHeader, "tok", dataplane.Header, "2")}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = runTCPTunnel(ctx, relay, dial, ctx, sessionTargets{http: http.NotFoundHandler()}, nil, slog.New(slog.DiscardHandler), nil)
	}()
	time.Sleep(300 * time.Millisecond)
	if n := dials.Load(); n != 0 {
		t.Fatalf("%d data connections while idle", n)
	}
	st.in <- &pb.TCPData{SessionId: "h1", Open: true, TargetAddr: dataplane.HTTPSessionTarget}
	for deadline := time.Now().Add(5 * time.Second); dials.Load() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no data connection after an HTTP session")
		}
	}
}

// primaryClient answers ConnectTCP with st and response header md: the
// relay's side, played by the test.
type primaryClient struct {
	pb.DispatcherClient
	st *chanStream
	md metadata.MD
}

func (c *primaryClient) ConnectTCP(context.Context, ...grpc.CallOption) (pb.Dispatcher_ConnectTCPClient, error) {
	return &primaryStream{chanStream: c.st, md: c.md}, nil
}

type primaryStream struct {
	grpc.ClientStream
	*chanStream
	md metadata.MD
}

func (s *primaryStream) Header() (metadata.MD, error) { return s.md, nil }
