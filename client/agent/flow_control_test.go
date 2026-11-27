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
	"google.golang.org/grpc/metadata"

	"github.com/nfltr/relay/proto/wire/chunking"
)

// flowStream is a relay stream that announced flow control.
type flowStream struct {
	blockingStream
}

func (s *flowStream) Header() (metadata.MD, error) {
	return metadata.Pairs(chunking.FlowControlMetadataKey, chunking.FlowControlResponses), nil
}

func uploadChunkRequest(txn string, index int, last bool, payload string) *pb.HTTPProxyRequest {
	h := map[string]*pb.HeaderValueList{chunking.HeaderUploadAcks: {HeaderValues: []string{"1"}}}
	chunking.SetChunkHeaders(h, index, last)
	r := &pb.HTTPProxyRequest{
		Request:    &pb.HTTPRequest{TransactionId: txn, Headers: h, Payload: []byte(payload)},
		Timestamps: &pb.Timestamps{},
	}
	if index == 0 {
		r.Request.Method, r.Request.Url = http.MethodPost, "/up"
	}
	return r
}

// pkg/agent runs the relay's flow control like the nfltr agent: a request
// body the relay acks streams to the backend (which starts reading before
// the last chunk arrives), and a cancel frame stops the request.
func TestProcessStreamStreamsUploadsAndHonoursCancel(t *testing.T) {
	firstByte := make(chan struct{})
	gone := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			close(gone)
			return
		}
		buf := make([]byte, 3)
		if _, err := io.ReadFull(r.Body, buf); err != nil {
			t.Errorf("first chunk: %v", err)
		}
		close(firstByte)
		rest, _ := io.ReadAll(r.Body)
		_, _ = w.Write(append(buf, rest...))
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

	stream.requests <- uploadChunkRequest("up", 0, false, "abc")
	select {
	case <-firstByte: // the backend reads chunk 0 while chunk 1 is still to come
	case <-time.After(5 * time.Second):
		t.Fatal("the backend got nothing before the last chunk: the body was buffered")
	}
	stream.requests <- uploadChunkRequest("up", 1, true, "def")
	var reply *pb.HTTPProxyResponse
	acks := 0
	for reply == nil {
		select {
		case m := <-stream.sent:
			switch {
			case m.Response.GetStatusCode() == 0 && chunking.IsAck(m.Response.GetHeaders()):
				acks++
			case m.Response.GetStatusCode() != 0:
				reply = m
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no response to the upload")
		}
	}
	if reply.Response.StatusCode != http.StatusOK || string(reply.Response.Payload) != "abcdef" || acks == 0 {
		t.Fatalf("upload: status %d body %q acks %d", reply.Response.StatusCode, reply.Response.Payload, acks)
	}

	slow := newTestProxyRequest(http.MethodGet, "/slow")
	slow.Request.TransactionId = "slow"
	stream.requests <- slow
	time.Sleep(100 * time.Millisecond)
	stream.requests <- chunking.CancelRequest("agent", "slow")
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("a cancel frame did not stop the local request")
	}
	cancel()
	<-done
}

// A multi-chunk request body without upload acks comes only from a relay
// before upload flow control: the agent refuses the request (502 naming
// why), drops its remaining chunks and keeps serving the stream.
func TestProcessStreamRefusesAnUnackedUpload(t *testing.T) {
	hits := make(chan string, 4)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r.URL.Path
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

	unacked := func(index int, last bool, payload string) *pb.HTTPProxyRequest {
		r := uploadChunkRequest("old", index, last, payload)
		delete(r.Request.Headers, chunking.HeaderUploadAcks)
		return r
	}
	stream.requests <- unacked(0, false, "abc")
	stream.requests <- unacked(1, true, "def")
	ok := newTestProxyRequest(http.MethodGet, "/after")
	ok.Request.TransactionId = "after"
	stream.requests <- ok

	got := map[string]*pb.HTTPResponse{}
	for len(got) < 2 {
		select {
		case m := <-stream.sent:
			if m.Response.GetStatusCode() != 0 {
				got[m.Response.TransactionId] = m.Response
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("responses: %v", got)
		}
	}
	if r := got["old"]; r.StatusCode != http.StatusBadGateway || string(r.Payload) != errUnackedUpload.Error() {
		t.Fatalf("unacked upload: %d %q; want 502 %q", r.StatusCode, r.Payload, errUnackedUpload)
	}
	if got["after"].StatusCode != http.StatusOK {
		t.Fatalf("the next request: %d", got["after"].StatusCode)
	}
	if p := <-hits; p != "/after" || len(hits) != 0 {
		t.Fatalf("backend saw %q (+%d): the refused upload or its chunk reached it", p, len(hits))
	}
	cancel()
	<-done
}
