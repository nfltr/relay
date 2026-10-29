// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpccodec

import (
	"bytes"
	"testing"
	"unsafe"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"
)

// TestLargeMessageCodec guards agent and relay memory on large transfers.
//   - A response chunk over pooledMessageLimit (8 MiB) is sent without a
//     copy of its payload: the last buffer is the payload itself, and the
//     encoding decodes to the same message in exactly proto.Size bytes (the
//     relay's max message size still holds).
//   - Any other large message gets a buffer of its own, not one that goes
//     back to grpc-go's pool.
//   - Small messages keep the pooled codec, and everything round-trips.
func TestLargeMessageCodec(t *testing.T) {
	c := NewLargeMessage()
	if c.Name() != "proto" {
		t.Fatalf("Name() = %q, want proto (the relay decodes by content-subtype)", c.Name())
	}
	payload := bytes.Repeat([]byte("nfltr"), (8<<20)/5)
	resp := &pb.HTTPProxyResponse{
		Response: &pb.HTTPResponse{
			TransactionId: "txn",
			StatusCode:    200,
			Deadline:      42,
			Headers:       map[string]*pb.HeaderValueList{"X-Chunk-Index": {HeaderValues: []string{"3"}}},
			Payload:       payload,
		},
		Timestamps: &pb.Timestamps{ResponseAtAgent: 7},
	}

	data := roundTrip(t, c, resp, &pb.HTTPProxyResponse{})
	last := data[len(data)-1].ReadOnlyData()
	if len(last) != len(payload) || unsafe.SliceData(last) != unsafe.SliceData(payload) {
		t.Fatal("the response chunk's payload was copied; its last buffer should be the payload itself")
	}
	if data.Len() != proto.Size(resp) {
		t.Fatalf("encoded %d bytes, proto.Size is %d", data.Len(), proto.Size(resp))
	}

	req := &pb.HTTPProxyRequest{Request: &pb.HTTPRequest{TransactionId: "txn", Payload: payload}}
	data = roundTrip(t, c, req, &pb.HTTPProxyRequest{})
	if _, own := data[0].(mem.SliceBuffer); len(data) != 1 || !own {
		t.Fatalf("an 8 MiB request was marshalled into %d buffers (%T), want one of its own, not grpc-go's pool", len(data), data[0])
	}

	small := &pb.HTTPProxyResponse{Response: &pb.HTTPResponse{TransactionId: "txn", Payload: payload[:4<<10]}}
	data = roundTrip(t, c, small, &pb.HTTPProxyResponse{})
	if _, own := data[0].(mem.SliceBuffer); own {
		t.Fatal("a 4 KiB message skipped the pool; only messages over pooledMessageLimit should")
	}
	data.Free()
}

// TestLargeUnmarshalReusesOneBuffer: a large message received as many
// frames decodes into a message that owns its bytes, so the one reused
// flattening buffer never leaks into, or corrupts, an earlier message.
func TestLargeUnmarshalReusesOneBuffer(t *testing.T) {
	c := NewLargeMessage()
	frames := func(m proto.Message) mem.BufferSlice {
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var out mem.BufferSlice
		for len(b) > 0 {
			n := min(len(b), 16<<10)
			out = append(out, mem.SliceBuffer(b[:n]))
			b = b[n:]
		}
		return out
	}
	chunk := func(fill byte) *pb.HTTPProxyResponse {
		return &pb.HTTPProxyResponse{Response: &pb.HTTPResponse{TransactionId: "txn", Payload: bytes.Repeat([]byte{fill}, 8<<20)}}
	}
	first, second := &pb.HTTPProxyResponse{}, &pb.HTTPProxyResponse{}
	if err := c.Unmarshal(frames(chunk('a')), first); err != nil {
		t.Fatal(err)
	}
	if err := c.Unmarshal(frames(chunk('b')), second); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(first, chunk('a')) || !proto.Equal(second, chunk('b')) {
		t.Fatal("a decoded chunk changed when the next one was decoded")
	}
	if len(flatBufs) != 1 {
		t.Fatalf("%d flattening buffers kept, want exactly 1", len(flatBufs))
	}
}

func roundTrip(t *testing.T, c encoding.CodecV2, in, out proto.Message) mem.BufferSlice {
	t.Helper()
	data, err := c.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, out) {
		t.Fatalf("%T did not round-trip", in)
	}
	return data
}

// TestTCPDataFrameSentWithoutCopy guards the tunnel's per-frame copy: a data
// frame encodes to exactly proto.Marshal's bytes with its data as the last
// buffer (not copied); any other TCPData takes the normal path.
func TestTCPDataFrameSentWithoutCopy(t *testing.T) {
	c := NewLargeMessage()
	data := bytes.Repeat([]byte("x"), 64<<10)
	for _, sid := range []string{"17", ""} {
		f := &pb.TCPData{SessionId: sid, Data: data}
		enc := roundTrip(t, c, f, &pb.TCPData{})
		want, _ := proto.Marshal(f)
		if got := enc.Materialize(); !bytes.Equal(got, want) {
			t.Fatalf("session %q: encoding differs from proto.Marshal", sid)
		}
		if last := enc[len(enc)-1].ReadOnlyData(); unsafe.SliceData(last) != unsafe.SliceData(data) {
			t.Fatalf("session %q: data was copied", sid)
		}
	}
	for _, f := range []*pb.TCPData{
		{SessionId: "1", Data: data, Close: true},
		{SessionId: "1", Data: data[:100]},
		{SessionId: "1", AgentId: "a", TargetAddr: "t:1", Open: true, E2Ee: true},
	} {
		for _, b := range roundTrip(t, c, f, &pb.TCPData{}) {
			if d := b.ReadOnlyData(); len(d) > 0 && unsafe.SliceData(d) == unsafe.SliceData(data) {
				t.Fatalf("%v: data aliased outside the data-frame path", f)
			}
		}
	}
}

// TestPoolSizeClasses guards Pool: a Get is served from the smallest power
// of two holding it (64 KiB + header must not take a 1 MiB buffer), and
// buffers over 1 MiB or not of a class are never pooled.
func TestPoolSizeClasses(t *testing.T) {
	for _, tc := range []struct{ size, cap int }{
		{1, 1 << 10}, {1 << 10, 1 << 10}, {1<<10 + 1, 2 << 10}, {16 << 10, 16 << 10},
		{64<<10 + 12, 128 << 10}, {1 << 20, 1 << 20}, {1<<20 + 1, 1<<20 + 1},
	} {
		b := Pool.Get(tc.size)
		if len(*b) != tc.size || cap(*b) != tc.cap {
			t.Fatalf("Get(%d): len %d cap %d, want cap %d", tc.size, len(*b), cap(*b), tc.cap)
		}
		Pool.Put(b)
	}
	odd := make([]byte, 3000)
	Pool.Put(&odd) // ignored
	if b := Pool.Get(2 << 10); cap(*b) != 2<<10 {
		t.Fatalf("Get(2 KiB) returned a foreign buffer, cap %d", cap(*b))
	}
}
