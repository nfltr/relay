// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/chunking"
)

// TestProcessStreamFullSlotsDoNotHoldTheReceiveLoop guards the HTTP
// tunnel's sibling of the stuck-client rule:
// with every handler slot taken, the receive loop keeps reading, so the
// frames that free a slot (a cancel here; an ack for a streamed response)
// still arrive. Before, the loop waited for a slot itself and the slot's
// handler waited for a frame only the loop reads: a deadlock until the
// stream ended.
func TestProcessStreamFullSlotsDoNotHoldTheReceiveLoop(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done() // holds its slot until cancelled
			return
		}
		_, _ = w.Write([]byte("fast"))
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
		done <- processStream(ctx, stream, "agent", routes, Config{RequestTimeout: 60, Concurrency: 1}, newBackendClient(Config{RequestTimeout: 60, Concurrency: 1}), slog.New(slog.DiscardHandler), nil, nil, nil)
	}()
	defer func() { cancel(); <-done }()

	slow := newTestProxyRequest(http.MethodGet, "/slow")
	slow.Request.TransactionId = "slow"
	fast := newTestProxyRequest(http.MethodGet, "/fast")
	fast.Request.TransactionId = "fast"
	stream.requests <- slow // takes the one slot
	time.Sleep(100 * time.Millisecond)
	stream.requests <- fast                                  // waits for a slot
	stream.requests <- chunking.CancelRequest("agent", "slow") // frees it, if the loop reads it
	deadline := time.After(5 * time.Second) // well within the request timeout
	for {
		select {
		case m := <-stream.sent:
			if m.GetResponse().GetTransactionId() == "fast" && m.GetResponse().GetStatusCode() == http.StatusOK {
				return
			}
		case <-deadline:
			t.Fatal("no answer to a request queued behind a full slot: the receive loop waits for the slot")
		}
	}
}
