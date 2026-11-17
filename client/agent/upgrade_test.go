// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/chunking"
)

// TestProcessStreamRelaysUpgrades: a relayed upgrade (chunking.IsUpgrade,
// chunk 0 of a streamed upload) reaches the backend without a body, its 101
// comes back at once as chunk 0 of a streamed response although the backend
// has sent nothing after it, the visitor's bytes (further upload chunks)
// reach the backend's connection and its bytes come back as further response
// chunks, and the visitor's end (the last upload chunk) closes the backend's
// connection, which ends the response with a last chunk. Before, the agent
// waited for a 101's body to fill a chunk: nothing ever came back.
func TestProcessStreamRelaysUpgrades(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != 0 || r.Header.Get("Transfer-Encoding") != "" {
			t.Errorf("upgrade request with a body: length %d, %v", r.ContentLength, r.TransferEncoding)
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		_, _ = io.Copy(conn, brw) // echo until the agent closes
	}))
	defer backend.Close()
	routes, err := parseRoutes([]Route{{Backend: backend.URL}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream := &flowStream{blockingStream{ctx: ctx, requests: make(chan *pb.HTTPProxyRequest, 8), sent: make(chan *pb.HTTPProxyResponse, 64)}}
	done := make(chan error, 1)
	go func() {
		done <- processStream(ctx, stream, "agent", routes, Config{RequestTimeout: 5, Concurrency: 4}, newBackendClient(Config{RequestTimeout: 5, Concurrency: 4}), slog.Default(), nil, nil, nil)
	}()
	next := func() *pb.HTTPProxyResponse { // the next response chunk, acks skipped
		for {
			select {
			case m := <-stream.sent:
				if m.Response.GetStatusCode() == 0 && !chunking.IsChunked(m.Response.GetHeaders()) {
					continue // an upload ack
				}
				return m
			case <-time.After(5 * time.Second):
				t.Fatal("no response chunk")
				return nil
			}
		}
	}

	head := uploadChunkRequest("ws", 0, false, "")
	head.Request.Method, head.Request.Url = http.MethodGet, "/ws"
	head.Request.Headers["Connection"] = &pb.HeaderValueList{HeaderValues: []string{"Upgrade"}}
	head.Request.Headers["Upgrade"] = &pb.HeaderValueList{HeaderValues: []string{"websocket"}}
	stream.requests <- head
	if m := next(); m.Response.StatusCode != http.StatusSwitchingProtocols || chunking.IsLastChunk(m.Response.Headers) {
		t.Fatalf("first answer: status %d headers %v; want the 101 as a chunk that is not the last", m.Response.StatusCode, m.Response.Headers)
	}
	stream.requests <- uploadChunkRequest("ws", 1, false, "ping")
	if m := next(); string(m.Response.Payload) != "ping" || chunking.GetChunkIndex(m.Response.Headers) != 1 {
		t.Fatalf("echo: %q (chunk %d), want \"ping\" as chunk 1", m.Response.Payload, chunking.GetChunkIndex(m.Response.Headers))
	}
	stream.requests <- uploadChunkRequest("ws", 2, true, "")
	if m := next(); !chunking.IsLastChunk(m.Response.Headers) {
		t.Fatalf("after the visitor's end: %+v, want the last chunk", m.Response)
	}
	cancel()
	<-done
}
