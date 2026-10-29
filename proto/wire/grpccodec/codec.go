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
	if data.Len() <= pooledMessageLimit {
		buf := data.MaterializeToBuffer(Pool) // no copy when it is one frame
		defer buf.Free()
		return proto.Unmarshal(buf.ReadOnlyData(), m)
	}
	var b []byte
	select {
	case b = <-flatBufs:
	default:
	}
	if cap(b) < data.Len() {
		b = make([]byte, data.Len())
	}
	b = b[:data.CopyTo(b[:data.Len()])]
	err := proto.Unmarshal(b, m) // copies bytes fields out of b
	select {
	case flatBufs <- b:
	default:
	}
	return err
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

// flatBufs keeps at most one flattening buffer for large Unmarshals: proto
// needs the received frames contiguous, and a fresh 8 MiB buffer per chunk
// cost a third of the relay's download throughput in GC. One buffer
// process-wide, unlike grpc-go's pool that keeps one per P plus victims.
var flatBufs = make(chan []byte, 1)

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
