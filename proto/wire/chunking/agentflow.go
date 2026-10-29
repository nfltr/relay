// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package chunking

import (
	"context"
	"sync"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/metadata"
)

// AgentFlow is an agent's side of the flow-control contract (flow.go) for
// the requests in flight on one relay stream: the relay's cancel and ack
// frames, and request bodies streamed under the upload window. Every agent
// (nfltr, pkg/agent, cmd/tunnel-agent) runs it the same way: its receive
// loop passes each message to Handle, calls Begin for each new request and
// StreamEnded when the stream ends; the request's handler calls Done.
//
// An agent using it sets FlowControlMetadataKey to FlowControlUploads in its
// connect metadata, and passes whether the relay announced flow control (the
// same key in the stream's response header) to NewAgentFlow.
type AgentFlow struct {
	relayAcks bool     // the relay acks response chunks
	inflight  sync.Map // transaction ID → *Request
	uploads   sync.Map // transaction ID → *Upload
}

// NewAgentFlow starts the flow state of one stream; relayAcks is whether the
// relay announced FlowControlMetadataKey.
func NewAgentFlow(relayAcks bool) *AgentFlow { return &AgentFlow{relayAcks: relayAcks} }

// Handle consumes a relay control frame or the next chunk of a streamed
// upload and reports whether it did; any other message is a new request.
// A chunk whose request is gone (answered or cancelled) is dropped.
func (f *AgentFlow) Handle(r *pb.HTTPRequest) bool {
	h := r.GetHeaders()
	switch {
	case IsControl(h):
		if v, ok := f.inflight.Load(r.GetTransactionId()); ok {
			v.(*Request).control(h)
		}
		return true
	case IsChunked(h) && GetChunkIndex(h) > 0:
		if v, ok := f.uploads.Load(r.GetTransactionId()); ok {
			v.(*Upload).Deliver(r.GetPayload(), IsLastChunk(h))
		}
		return true
	}
	return false
}

// Request is one request registered by Begin.
type Request struct {
	// Ctx ends when the relay cancels the request (its caller is gone), the
	// stream ends, or Done.
	Ctx context.Context
	// Body streams the request body when the relay acks its chunks; nil
	// when the whole body is in the request message, or arrives unacked
	// from a relay that predates upload acks (the caller refuses it).
	Body *Upload
	// Acks carries the relay's acks of this response's chunks, for
	// AwaitAck; nil when the relay sends none.
	Acks <-chan struct{}

	acks   chan struct{}
	cancel context.CancelFunc
	flow   *AgentFlow
	txn    string
}

// Begin registers a new request on the receive loop, before any of its
// frames or further chunks can arrive. send delivers the upload's acks.
func (f *AgentFlow) Begin(ctx context.Context, r *pb.HTTPRequest, send func(*pb.HTTPProxyResponse) error) *Request {
	txn := r.GetTransactionId()
	reqCtx, cancel := context.WithCancel(ctx)
	q := &Request{Ctx: reqCtx, cancel: cancel, flow: f, txn: txn}
	if f.relayAcks {
		q.acks = make(chan struct{}, ResponseWindow)
		q.Acks = q.acks
	}
	if h := r.GetHeaders(); IsChunked(h) && !IsLastChunk(h) && WantsUploadAcks(h) {
		q.Body = NewUpload(reqCtx, func(i int) { _ = send(AckResponse(txn, i)) })
		q.Body.Deliver(r.GetPayload(), false)
		f.uploads.Store(txn, q.Body)
	}
	f.inflight.Store(txn, q)
	return q
}

// Done ends the request: its frames and remaining chunks are dropped.
func (q *Request) Done() {
	q.flow.inflight.Delete(q.txn)
	q.flow.uploads.Delete(q.txn)
	q.cancel()
}

// control applies a relay cancel or ack frame. An ack never blocks the
// receive loop: at most ResponseWindow are outstanding, the channel's size.
func (q *Request) control(h map[string]*pb.HeaderValueList) {
	switch {
	case IsCancel(h):
		q.cancel()
	case q.acks != nil:
		select {
		case q.acks <- struct{}{}:
		default:
		}
	}
}

// StreamEnded cancels the requests whose body streams from the ended
// stream: their remaining chunks will never come. Other requests finish on
// their own (as before flow control, their responses just cannot be sent).
// allow:wrapper — the stream-end step of the contract every agent runs.
func (f *AgentFlow) StreamEnded() {
	f.uploads.Range(func(txn, _ any) bool {
		if v, ok := f.inflight.Load(txn); ok {
			v.(*Request).cancel()
		}
		return true
	})
}

// RelayAcks reports whether the relay announced flow control
// (FlowControlMetadataKey) in the agent stream's response header.
func RelayAcks(stream interface{ Header() (metadata.MD, error) }) bool {
	h, err := stream.Header()
	return err == nil && len(h.Get(FlowControlMetadataKey)) > 0
}

// AwaitAck holds response chunk index back until chunk
// index-ResponseWindow was acknowledged (nil acks: never).
func AwaitAck(ctx context.Context, acks <-chan struct{}, index int) error {
	if acks == nil || index < ResponseWindow {
		return nil
	}
	select {
	case <-acks:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
