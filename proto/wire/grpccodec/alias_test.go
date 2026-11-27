// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpccodec

import (
	"bytes"
	"testing"
	"unsafe"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// TestBodyPayloadFields: the field numbers unmarshalAliasingPayload parses
// by are the descriptors' (a renumbering would decode the wrong field).
func TestBodyPayloadFields(t *testing.T) {
	for _, tc := range []struct {
		m           proto.Message
		body, field string
		num         protowire.Number
	}{
		{&pb.HTTPProxyResponse{}, "response", "payload", responsePayloadField},
		{&pb.HTTPProxyRequest{}, "request", "payload", requestPayloadField},
	} {
		body := tc.m.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(tc.body))
		if body.Number() != bodyField {
			t.Fatalf("%T.%s is field %d, want %d", tc.m, tc.body, body.Number(), bodyField)
		}
		if f := body.Message().Fields().ByName(protoreflect.Name(tc.field)); f.Number() != tc.num {
			t.Fatalf("%s.%s is field %d, want %d", body.Message().Name(), tc.field, f.Number(), tc.num)
		}
	}
}

// aliasingCases are encodings of HTTP body chunk messages, valid and not,
// with the merge cases protobuf allows: a body or payload given twice,
// unknown fields around them, a body or payload of the wrong wire type.
func aliasingCases() [][]byte {
	headers := map[string]*pb.HeaderValueList{"X-Chunk-Index": {HeaderValues: []string{"3"}}, "B": {HeaderValues: []string{"1", "2"}}}
	resp := func(p string) []byte {
		b, _ := proto.Marshal(&pb.HTTPProxyResponse{
			Response:   &pb.HTTPResponse{TransactionId: "txn", Headers: headers, Payload: []byte(p), Deadline: 9, StatusCode: 200},
			Timestamps: &pb.Timestamps{ResponseAtAgent: 7}, Routing: &pb.RoutingInfo{AgentId: "a"},
		})
		return b
	}
	req, _ := proto.Marshal(&pb.HTTPProxyRequest{Request: &pb.HTTPRequest{Method: "POST", Url: "/u", Headers: headers, Payload: []byte("body"), TransactionId: "t"}})
	unknown := protowire.AppendString(protowire.AppendTag(nil, 99, protowire.BytesType), "unknown")
	bodyOf := func(inner []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, bodyField, protowire.BytesType), inner)
	}
	payload := protowire.AppendString(protowire.AppendTag(nil, responsePayloadField, protowire.BytesType), "second")
	return [][]byte{
		resp("hello"), resp(""), resp(string(bytes.Repeat([]byte("x"), 70<<10))), req, nil,
		append(resp("first"), resp("second")...),
		append(append(unknown, resp("p")...), unknown...),
		append(resp("p"), bodyOf(append(append(unknown, payload...), unknown...))...),
		append(resp("p"), bodyOf(protowire.AppendVarint(protowire.AppendTag(nil, responsePayloadField, protowire.VarintType), 5))...),
		append(resp("p"), protowire.AppendVarint(protowire.AppendTag(nil, bodyField, protowire.VarintType), 1)...),
		bodyOf(nil),
		resp("hello")[:20],
		append(resp("p"), 0x0a, 0x80),
		append(resp("p"), bodyOf([]byte{0x1a, 0x05, 'a'})...),
	}
}

// TestUnmarshalAliasingPayloadParity: unmarshalAliasingPayload decodes
// every case to what proto.Unmarshal does (or fails where it fails), and a
// payload it returns is the input's own bytes, capped.
func TestUnmarshalAliasingPayloadParity(t *testing.T) {
	for i, b := range aliasingCases() {
		checkAliasingParity(t, i, b)
	}
}

func checkAliasingParity(t *testing.T, i int, b []byte) {
	t.Helper()
	for _, newMsg := range []func() proto.Message{
		func() proto.Message { return &pb.HTTPProxyResponse{} },
		func() proto.Message { return &pb.HTTPProxyRequest{} },
	} {
		want, got := newMsg(), newMsg()
		wantErr := proto.Unmarshal(b, want)
		in := bytes.Clone(b)
		gotErr := unmarshalAliasingPayload(in, got)
		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("case %d %T: error %v, proto.Unmarshal's %v", i, got, gotErr, wantErr)
		}
		if wantErr != nil {
			continue
		}
		if !proto.Equal(got, want) {
			t.Fatalf("case %d %T: decoded %v, proto.Unmarshal %v", i, got, got, want)
		}
		var p []byte
		switch m := got.(type) {
		case *pb.HTTPProxyResponse:
			p = m.GetResponse().GetPayload()
		case *pb.HTTPProxyRequest:
			p = m.GetRequest().GetPayload()
		}
		if len(p) > 0 {
			start := uintptr(unsafe.Pointer(unsafe.SliceData(in)))
			at := uintptr(unsafe.Pointer(unsafe.SliceData(p)))
			if at < start || at+uintptr(len(p)) > start+uintptr(len(in)) || cap(p) != len(p) {
				t.Fatalf("case %d %T: payload is not the input's bytes, capped", i, got)
			}
		}
	}
}

// FuzzUnmarshalAliasingPayload: any input decodes as proto.Unmarshal
// decodes it.
func FuzzUnmarshalAliasingPayload(f *testing.F) {
	for _, b := range aliasingCases() {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) { checkAliasingParity(t, 0, b) })
}
