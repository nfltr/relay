// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package chunking

import (
	"strconv"

	"github.com/nfltr/relay/proto/pb"
)

// Flow control for chunked HTTP responses over the agent's one multiplexed
// stream. Two relay→agent frames, HTTPProxyRequests that carry no request:
//
//   - cancel: the caller of the transaction is gone (client disconnected,
//     stalled or timed out), so the agent stops producing that response.
//     Without it an aborted download streamed on until the file ended.
//   - ack: the relay wrote chunk N of the response to its client. An agent
//     keeps at most ResponseWindow chunks of one response unacknowledged, so
//     a slow client holds that transaction back (not the whole stream) and
//     the relay buffers at most ResponseWindow chunks of it.
//
// Both ends opt in with FlowControlMetadataKey (the agent in its connect
// metadata, the relay in its response header), so neither sends a frame the
// other would misread and an agent never waits for acks an older relay never
// sends.
//
// Uploads run the same window the other way. The relay marks every chunk of
// a multi-chunk request body with HeaderUploadAcks and keeps at most
// UploadWindow of them unacknowledged; an ack is an agent→relay
// HTTPProxyResponse carrying HeaderAck (AckResponse) once the agent's local
// request consumed that chunk. An agent that sets FlowControlMetadataKey to
// FlowControlUploads (or higher) streams such a body (Upload) and acks it; for
// any other agent the relay strips the header and acks each chunk itself once
// it is on the agent's stream, so that agent keeps reading bodies whole.
const (
	HeaderCancel     = "X-Nfltr-Cancel"
	HeaderAck        = "X-Nfltr-Ack"
	HeaderUploadAcks = "X-Nfltr-Upload-Acks"

	FlowControlMetadataKey = "x-tunnel-flow-control"

	// FlowControlResponses is the FlowControlMetadataKey value of an agent
	// that reads cancel/ack frames; FlowControlUploads adds upload acks.
	FlowControlResponses = "1"
	FlowControlUploads   = "2"

	// ResponseWindow is how many chunks of one response may be in flight.
	ResponseWindow = 4
	// UploadWindow is how many chunks of one request body may be in flight.
	UploadWindow = 4
)

// AcksUploads reports whether an agent's FlowControlMetadataKey value says
// it streams request bodies and acks their chunks.
func AcksUploads(level string) bool {
	n, err := strconv.Atoi(level)
	return err == nil && n >= 2
}

// WantsUploadAcks reports whether the relay asks for acks of this request
// body's chunks.
func WantsUploadAcks(h map[string]*pb.HeaderValueList) bool {
	_, ok := h[HeaderUploadAcks]
	return ok
}

// AckResponse builds the agent→relay frame acknowledging that chunk index
// of transactionID's request body was consumed.
func AckResponse(transactionID string, index int) *pb.HTTPProxyResponse {
	return &pb.HTTPProxyResponse{
		Response: &pb.HTTPResponse{
			TransactionId: transactionID,
			Headers:       map[string]*pb.HeaderValueList{HeaderAck: {HeaderValues: []string{strconv.Itoa(index)}}},
		},
		Timestamps: &pb.Timestamps{},
		Routing:    &pb.RoutingInfo{},
	}
}

// CancelRequest builds the cancel frame for transactionID on agentID.
// allow:wrapper — names one frame of the flow-control contract.
func CancelRequest(agentID, transactionID string) *pb.HTTPProxyRequest {
	return controlFrame(agentID, transactionID, HeaderCancel, "1")
}

// AckRequest builds the frame acknowledging chunk index of transactionID.
// allow:wrapper — names one frame of the flow-control contract.
func AckRequest(agentID, transactionID string, index int) *pb.HTTPProxyRequest {
	return controlFrame(agentID, transactionID, HeaderAck, strconv.Itoa(index))
}

func controlFrame(agentID, transactionID, header, value string) *pb.HTTPProxyRequest {
	return &pb.HTTPProxyRequest{
		Request: &pb.HTTPRequest{
			TransactionId: transactionID,
			Headers:       map[string]*pb.HeaderValueList{header: {HeaderValues: []string{value}}},
		},
		Timestamps: &pb.Timestamps{},
		Routing:    &pb.RoutingInfo{AgentId: agentID},
	}
}

// IsCancel reports whether h marks a cancel frame.
func IsCancel(h map[string]*pb.HeaderValueList) bool {
	_, ok := h[HeaderCancel]
	return ok
}

// IsAck reports whether h marks an ack frame.
func IsAck(h map[string]*pb.HeaderValueList) bool {
	_, ok := h[HeaderAck]
	return ok
}

// IsControl reports whether h marks a cancel or ack frame.
func IsControl(h map[string]*pb.HeaderValueList) bool { return IsCancel(h) || IsAck(h) }
