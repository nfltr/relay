// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpccodec

import (
	"bytes"
	"testing"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"
)

// BenchmarkUnmarshalBodyChunk: the codec decoding one HTTP body chunk as
// grpc-go hands it over (16 KiB HTTP/2 frames): a 1 MiB response chunk (the
// agent's chunk size, chunking.MaxPayload) and a 64 KiB one on the relay,
// a 1 MiB request chunk on the agent; parallel/ as many agent streams at
// once. B/op and allocs/op are the decode's own.
func BenchmarkUnmarshalBodyChunk(b *testing.B) {
	headers := map[string]*pb.HeaderValueList{"X-Chunk-Index": {HeaderValues: []string{"3"}}, "X-Chunked": {HeaderValues: []string{"true"}}}
	resp := func(n int) proto.Message {
		return &pb.HTTPProxyResponse{
			Response:   &pb.HTTPResponse{TransactionId: "0123456789abcdef", StatusCode: 200, Headers: headers, Payload: bytes.Repeat([]byte("x"), n)},
			Timestamps: &pb.Timestamps{ResponseAtAgent: 7}, Routing: &pb.RoutingInfo{AgentId: "agent"},
		}
	}
	req := &pb.HTTPProxyRequest{
		Request:    &pb.HTTPRequest{TransactionId: "0123456789abcdef", Method: "POST", Url: "/up", Headers: headers, Payload: bytes.Repeat([]byte("x"), 1<<20)},
		Timestamps: &pb.Timestamps{RequestAtHttpServer: 7}, Routing: &pb.RoutingInfo{AgentId: "agent"},
	}
	c := NewLargeMessage()
	for _, tc := range []struct {
		name string
		msg  proto.Message
	}{{"response-1MiB", resp(1 << 20)}, {"response-64KiB", resp(64 << 10)}, {"request-1MiB", req}} {
		enc, err := proto.Marshal(tc.msg)
		if err != nil {
			b.Fatal(err)
		}
		frames := func() mem.BufferSlice {
			var out mem.BufferSlice
			for rest := enc; len(rest) > 0; {
				n := min(len(rest), 16<<10)
				out = append(out, mem.SliceBuffer(rest[:n]))
				rest = rest[n:]
			}
			return out
		}()
		decode := func(b *testing.B) {
			m := tc.msg.ProtoReflect().New().Interface()
			if err := c.Unmarshal(frames, m); err != nil {
				b.Fatal(err)
			}
		}
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(enc)))
			b.ReportAllocs()
			for b.Loop() {
				decode(b)
			}
		})
		b.Run("parallel/"+tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(enc)))
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					decode(b)
				}
			})
		})
	}
}
