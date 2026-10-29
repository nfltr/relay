// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package chunking

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
)

func uploadChunk(txn string, index int, last bool, payload string) *pb.HTTPRequest {
	h := map[string]*pb.HeaderValueList{HeaderUploadAcks: {HeaderValues: []string{"1"}}}
	SetChunkHeaders(h, index, last)
	return &pb.HTTPRequest{TransactionId: txn, Headers: h, Payload: []byte(payload)}
}

// The agent side of the contract, as every agent's receive loop drives it:
// a streamed upload arrives through Handle, frames reach their request, and
// a request that is done drops its late chunks.
func TestAgentFlowStreamsUploadsAndRoutesFrames(t *testing.T) {
	f := NewAgentFlow(true)
	var acked []int
	send := func(r *pb.HTTPProxyResponse) error {
		if !IsAck(r.Response.Headers) || r.Response.TransactionId != "t1" {
			t.Errorf("sent %v, want an ack of t1", r)
		}
		acked = append(acked, len(acked))
		return nil
	}
	first := uploadChunk("t1", 0, false, "ab")
	if f.Handle(first) {
		t.Fatal("a new request was consumed as a frame")
	}
	q := f.Begin(context.Background(), first, send)
	if q.Body == nil || q.Acks == nil {
		t.Fatalf("Begin: body %v acks %v, want both", q.Body, q.Acks)
	}
	for i, p := range []string{"cd", "ef"} {
		if !f.Handle(uploadChunk("t1", i+1, i == 1, p)) {
			t.Fatal("an upload chunk was not consumed")
		}
	}
	body, err := io.ReadAll(q.Body)
	if err != nil || string(body) != "abcdef" {
		t.Fatalf("body %q, %v", body, err)
	}
	if len(acked) < 2 {
		t.Fatalf("acked %d chunks, want the ones read", len(acked))
	}

	if !f.Handle(AckRequest("a", "t1", 0).Request) {
		t.Fatal("an ack frame was not consumed")
	}
	select {
	case <-q.Acks:
	case <-time.After(time.Second):
		t.Fatal("the ack did not reach its request")
	}
	f.Handle(CancelRequest("a", "t1").Request)
	if q.Ctx.Err() == nil {
		t.Fatal("the cancel frame did not cancel the request")
	}
	q.Done()
	if !f.Handle(uploadChunk("t1", 3, true, "late")) {
		t.Fatal("a late chunk of a finished request was taken for a new request")
	}
}

func TestAgentFlowWithoutRelayAcks(t *testing.T) {
	f := NewAgentFlow(false)
	whole := &pb.HTTPRequest{TransactionId: "t2", Payload: []byte("x")}
	q := f.Begin(context.Background(), whole, nil)
	if q.Body != nil || q.Acks != nil {
		t.Fatalf("Begin: body %v acks %v, want neither", q.Body, q.Acks)
	}
	if err := AwaitAck(q.Ctx, q.Acks, 100); err != nil {
		t.Fatalf("AwaitAck without acks: %v", err)
	}
	up := f.Begin(context.Background(), uploadChunk("t3", 0, false, "a"), func(*pb.HTTPProxyResponse) error { return nil })
	f.StreamEnded()
	if up.Ctx.Err() == nil {
		t.Fatal("a request waiting for upload chunks outlived its stream")
	}
	if q.Ctx.Err() != nil {
		t.Fatal("StreamEnded cancelled a request whose body was whole")
	}
}
