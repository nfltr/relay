// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/chunking"
	"github.com/nfltr/relay/proto/wire/dataplane"
)

// A response whose body fails mid-way (the backend died, or the agent is
// closing and its backend request is cancelled) must reach the relay as an
// incomplete body, never as a whole one: 2026-10-15, a 3-replica relay saw
// visitors get a clean end of a truncated body after the agent closed.

const cutHead = 128 << 10

// cutBackend writes cutHead bytes, flushes, then dies (/die: its
// connection closes mid-body) or waits for its request to end (/wait).
func cutBackend(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, cutHead))
		w.(http.Flusher).Flush()
		if r.URL.Path == "/wait" {
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
			return
		}
		if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// TestTunnelHandlerCutsAFailedBody: on a link session, a body the backend
// cut ends as an error at the relay, not with the terminating chunk.
func TestTunnelHandlerCutsAFailedBody(t *testing.T) {
	h, err := NewTunnelHandler(Config{AgentID: "a1", Routes: []Route{{Backend: cutBackend(t).URL}}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)
	resp, err := http.Get(front.URL + "/die")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	n, err := io.Copy(io.Discard, resp.Body)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("body ended with %v after %d bytes, want unexpected EOF", err, n)
	}
}

// TestHTTPSessionCutWhenItsInputEnds: a link session's input ends while
// its response is mid-body, as the tunnel's teardown ends every session's
// input when the agent closes (closeAll) while frames still go out; the
// backend request is cancelled and what the relay got is an incomplete
// body, not the terminating chunk.
func TestHTTPSessionCutWhenItsInputEnds(t *testing.T) {
	h, err := NewTunnelHandler(Config{AgentID: "a1", Routes: []Route{{Backend: cutBackend(t).URL}}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	st := newChanStream(t, 8, 1024)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = serveTCPStream(ctx, st, sessionTargets{http: h, noRaw: true}, nil, nil, slog.New(slog.DiscardHandler), nil, nil)
	}()
	st.in <- &pb.TCPData{SessionId: "h1", Open: true, TargetAddr: dataplane.HTTPSessionTarget}
	st.in <- &pb.TCPData{SessionId: "h1", Data: []byte("GET /wait HTTP/1.1\r\nHost: agent\r\n\r\n")}
	var got bytes.Buffer
	ended := false
	for !ended {
		select {
		case f := <-st.out:
			got.Write(f.GetData())
			ended = f.GetClose()
			if got.Len() >= cutHead && len(f.GetData()) > 0 && f.GetSessionId() == "h1" {
				st.in <- &pb.TCPData{SessionId: "h1", Close: true, Half: true}
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("the session did not end: %d bytes", got.Len())
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(&got), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := io.Copy(io.Discard, resp.Body); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("body ended with %v after %d bytes, want unexpected EOF", err, n)
	}
}

// TestSendResponseNeverEndsAFailedBody: on the gRPC stream, a failed body
// gets no last chunk (the relay then ends the visitor's response as an
// error), whether the backend died or the agent is closing.
func TestSendResponseNeverEndsAFailedBody(t *testing.T) {
	backend := cutBackend(t)
	for _, tc := range []struct {
		path  string
		close bool
	}{{"/die", false}, {"/wait", true}} {
		for i := range 20 { // the agent-closing end was a race
			ctx, cancel := context.WithCancel(t.Context())
			msg := newTestProxyRequest("GET", tc.path)
			fwd := resolvedForward{targetBase: backend.URL, strippedPath: tc.path}
			resp, err := forwardRequest(ctx, http.DefaultClient, msg, fwd, "a1", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.close {
				time.AfterFunc(50*time.Millisecond, cancel)
			}
			stream := &stubSendStream{}
			n, sendErr := sendResponse(ctx, stream.Send, resp, msg, fwd, nil)
			_ = resp.Body.Close()
			cancel()
			for _, m := range stream.sent {
				h := m.GetResponse().GetHeaders()
				if !chunking.IsChunked(h) || chunking.IsLastChunk(h) {
					t.Fatalf("%s %d: sent the end of a failed body (%d bytes)", tc.path, i, n)
				}
			}
			if sendErr == nil {
				t.Fatalf("%s %d: no error for a failed body", tc.path, i)
			}
		}
	}
}
