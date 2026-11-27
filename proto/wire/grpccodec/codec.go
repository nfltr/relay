// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package grpccodec holds the gRPC codec shared by the agent client
// (grpcclient) and the relay server (grpcfactory).
package grpccodec

import (
	"encoding/binary"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/encoding"
	protocodec "google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// pooledMessageLimit is the largest message grpc-go's default buffer pool
// serves from a size class (its largest tier, 1 MiB).
const pooledMessageLimit = 1 << 20

// largeMessageCodec is grpc-go's proto codec, except for messages over
// pooledMessageLimit (the 8 MiB body chunks between agent and relay, both
// ways):
//
//   - they are not put in grpc-go's shared buffer pool. Above its largest
//     tier that pool is one sync.Pool of any-size buffers: every P that sent
//     or received a chunk keeps an 8 MiB buffer in its per-P cache, and the
//     GC keeps them another cycle in the victim cache. Measured: 24-40 MiB of
//     a share agent's live heap and 32 MiB of the relay's, idle, doubled by
//     GOGC=100.
//   - an HTTPProxyResponse (a response chunk) is sent without copying its
//     payload: the message is encoded without it, the payload's field
//     appended, and the payload itself handed to the transport as the last
//     buffer. That is the standard encoding, in the same number of bytes;
//     it relies on gRPC's rule that a message is not modified after SendMsg.
//   - a received body chunk (HTTPProxyResponse, HTTPProxyRequest) is decoded
//     with its payload aliasing the one buffer its frames are copied into
//     (unmarshalAliasingPayload): one copy and one allocation per chunk.
//
// Smaller messages use Pool (pool.go); data frames of the TCP tunnel are
// sent without copying their data (marshalTCPData).
type largeMessageCodec struct{ encoding.CodecV2 }

// NewLargeMessage returns the codec for the agent's client conn
// (grpc.ForceCodecV2) and the relay's server (grpc.ForceServerCodecV2). Its
// name stays "proto", the content-subtype both ends expect.
func NewLargeMessage() encoding.CodecV2 {
	return largeMessageCodec{encoding.GetCodecV2(protocodec.Name)}
}

func (c largeMessageCodec) Marshal(v any) (mem.BufferSlice, error) {
	m, ok := v.(proto.Message)
	if !ok {
		return c.CodecV2.Marshal(v)
	}
	if f, ok := m.(*pb.TCPData); ok && isDataFrame(f) {
		return marshalTCPData(f), nil
	}
	size := proto.Size(m)
	opts := proto.MarshalOptions{UseCachedSize: true} // sized just above
	if size <= pooledMessageLimit {
		if mem.IsBelowBufferPoolingThreshold(size) {
			b, err := opts.Marshal(m)
			return mem.BufferSlice{mem.SliceBuffer(b)}, err
		}
		buf := Pool.Get(size)
		if _, err := opts.MarshalAppend((*buf)[:0], m); err != nil {
			Pool.Put(buf)
			return nil, err
		}
		return mem.BufferSlice{mem.NewBuffer(buf, Pool)}, nil
	}
	if r, ok := m.(*pb.HTTPProxyResponse); ok && len(r.GetResponse().GetPayload()) > 0 {
		return marshalAliasingPayload(r)
	}
	b, err := opts.Marshal(m)
	if err != nil {
		return nil, err
	}
	return mem.BufferSlice{mem.SliceBuffer(b)}, nil
}

func (c largeMessageCodec) Unmarshal(data mem.BufferSlice, v any) error {
	m, ok := v.(proto.Message)
	if !ok {
		return c.CodecV2.Unmarshal(data, v)
	}
	if data.Len() > pooledMessageLimit && bodyPayloadField(m) != 0 {
		// A body chunk (chunking.MaxPayload): smaller ones keep the pooled
		// path, as a buffer of the whole message would round a 64 KiB
		// payload's allocation up a page (BenchmarkUnmarshalBodyChunk).
		b := make([]byte, data.Len())
		data.CopyTo(b)
		return unmarshalAliasingPayload(b, m)
	}
	buf := data.MaterializeToBuffer(Pool) // no copy when it is one frame; over 1 MiB a buffer of its own (Pool)
	defer buf.Free()
	return proto.Unmarshal(buf.ReadOnlyData(), m)
}

// Field numbers of the HTTP body chunk messages (TestBodyPayloadFields
// checks them against the descriptors): the body is field 1 of
// HTTPProxyResponse and HTTPProxyRequest, its payload field 3 of
// HTTPResponse and 4 of HTTPRequest.
const (
	bodyField            protowire.Number = 1
	responsePayloadField protowire.Number = 3
	requestPayloadField  protowire.Number = 4
)

// bodyPayloadField is the payload's field number in m's body, or 0 when m
// is not an HTTP body chunk message.
func bodyPayloadField(m proto.Message) protowire.Number {
	switch m.(type) {
	case *pb.HTTPProxyResponse:
		return responsePayloadField
	case *pb.HTTPProxyRequest:
		return requestPayloadField
	}
	return 0
}

// span is b[from:to] of a message's encoding.
type span struct{ from, to int }

// unmarshalAliasingPayload decodes b into m (an HTTPProxyResponse or
// HTTPProxyRequest) as proto.Unmarshal does, except that the body's payload
// is b's own bytes (capped, so an append copies) instead of a copy: b is a
// buffer the message owns, so a chunk costs one copy (the frames into b)
// instead of two (frames into a flat buffer, then the payload out of it)
// and one allocation instead of two. Protobuf decoding is a merge of the
// fields in their order (proto.UnmarshalOptions.Merge), so m is decoded from
// b's fields except the body's, the body from its fields except the
// payload, and the payload is set last (the last occurrence wins, as in
// proto.Unmarshal). Guards: TestUnmarshalAliasingPayloadParity,
// FuzzUnmarshalAliasingPayload; BenchmarkUnmarshalBodyChunk.
func unmarshalAliasingPayload(b []byte, m proto.Message) error {
	payloadNum := bodyPayloadField(m)
	var outerBuf, innerBuf [4]span
	outer, inner := outerBuf[:0], innerBuf[:0]
	var payload []byte
	hasBody := false
	ok := eachField(b, 0, func(num protowire.Number, typ protowire.Type, f span, val int) bool {
		if num != bodyField || typ != protowire.BytesType {
			outer = appendSpan(outer, f)
			return true
		}
		hasBody = true
		body, n := protowire.ConsumeBytes(b[val:])
		if n < 0 {
			return false
		}
		start := val + n - len(body)
		return eachField(b[:start+len(body)], start, func(num protowire.Number, typ protowire.Type, f span, val int) bool {
			if num != payloadNum || typ != protowire.BytesType {
				inner = appendSpan(inner, f)
				return true
			}
			v, n := protowire.ConsumeBytes(b[val:])
			if n < 0 {
				return false
			}
			payload = v[:len(v):len(v)]
			return true
		})
	})
	if !ok {
		return proto.Unmarshal(b, m) // malformed: proto's own error
	}
	proto.Reset(m)
	opts := proto.UnmarshalOptions{Merge: true}
	for _, s := range outer {
		if err := opts.Unmarshal(b[s.from:s.to], m); err != nil {
			return proto.Unmarshal(b, m)
		}
	}
	if !hasBody {
		return nil
	}
	var body proto.Message
	var setPayload func([]byte)
	switch m := m.(type) {
	case *pb.HTTPProxyResponse:
		if m.Response == nil {
			m.Response = &pb.HTTPResponse{}
		}
		body, setPayload = m.Response, func(p []byte) { m.Response.Payload = p }
	case *pb.HTTPProxyRequest:
		if m.Request == nil {
			m.Request = &pb.HTTPRequest{}
		}
		body, setPayload = m.Request, func(p []byte) { m.Request.Payload = p }
	}
	for _, s := range inner {
		if err := opts.Unmarshal(b[s.from:s.to], body); err != nil {
			return proto.Unmarshal(b, m)
		}
	}
	if len(payload) > 0 {
		setPayload(payload)
	}
	return nil
}

// eachField calls f for every field of b[from:] with its number, wire type,
// span (tag included) and the offset of its value; false when b is
// malformed or f returns false.
func eachField(b []byte, from int, f func(protowire.Number, protowire.Type, span, int) bool) bool {
	for i := from; i < len(b); {
		num, typ, n := protowire.ConsumeTag(b[i:])
		if n < 0 {
			return false
		}
		m := protowire.ConsumeFieldValue(num, typ, b[i+n:])
		if m < 0 {
			return false
		}
		if !f(num, typ, span{i, i + n + m}, i+n) {
			return false
		}
		i += n + m
	}
	return true
}

// appendSpan appends s to spans, merging it into the last span it
// continues.
func appendSpan(spans []span, s span) []span {
	if k := len(spans) - 1; k >= 0 && spans[k].to == s.from {
		spans[k].to = s.to
		return spans
	}
	return append(spans, s)
}

// isDataFrame reports whether f is a tunnel data frame worth not copying:
// a session id and pooled-size data, nothing else.
func isDataFrame(f *pb.TCPData) bool {
	return !mem.IsBelowBufferPoolingThreshold(len(f.GetData())) && f.GetAgentId() == "" && f.GetTargetAddr() == "" &&
		!f.GetOpen() && !f.GetClose() && !f.GetE2Ee() && len(f.ProtoReflect().GetUnknown()) == 0
}

// marshalTCPData encodes a data frame exactly as proto.Marshal does
// (session_id, then data), except that the data is handed to the transport
// as the last buffer instead of being copied into a marshal buffer: one copy
// less per tunnel frame on each sender. Like marshalAliasingPayload it
// relies on gRPC's rule that a message is not modified after SendMsg.
func marshalTCPData(f *pb.TCPData) mem.BufferSlice {
	sid, data := f.GetSessionId(), f.GetData()
	head := make([]byte, 0, 2+2*binary.MaxVarintLen64+len(sid))
	if sid != "" {
		head = protowire.AppendTag(head, 1, protowire.BytesType)
		head = protowire.AppendString(head, sid)
	}
	head = protowire.AppendTag(head, 3, protowire.BytesType)
	head = protowire.AppendVarint(head, uint64(len(data)))
	return mem.BufferSlice{mem.SliceBuffer(head), mem.SliceBuffer(data)}
}

// marshalAliasingPayload encodes m as [m without response] [response field
// header] [response without payload] [payload field header] [payload], the
// last being m.Response.Payload itself.
func marshalAliasingPayload(m *pb.HTTPProxyResponse) (mem.BufferSlice, error) {
	outer, inner := m.ProtoReflect(), m.GetResponse().ProtoReflect()
	respField := outer.Descriptor().Fields().ByName("response")
	payloadField := inner.Descriptor().Fields().ByName("payload")
	payload := m.GetResponse().GetPayload()

	head, err := proto.Marshal(without(outer, respField).Interface())
	if err != nil {
		return nil, err
	}
	resp, err := proto.Marshal(without(inner, payloadField).Interface())
	if err != nil {
		return nil, err
	}
	respLen := len(resp) + protowire.SizeTag(payloadField.Number()) + protowire.SizeBytes(len(payload))
	head = protowire.AppendTag(head, respField.Number(), protowire.BytesType)
	head = protowire.AppendVarint(head, uint64(respLen))
	head = append(head, resp...)
	head = protowire.AppendTag(head, payloadField.Number(), protowire.BytesType)
	head = protowire.AppendVarint(head, uint64(len(payload)))
	return mem.BufferSlice{mem.SliceBuffer(head), mem.SliceBuffer(payload)}, nil
}

// without is a shallow copy of m without field skip.
func without(m protoreflect.Message, skip protoreflect.FieldDescriptor) protoreflect.Message {
	c := m.New()
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd != skip {
			c.Set(fd, v)
		}
		return true
	})
	c.SetUnknown(m.GetUnknown())
	return c
}
