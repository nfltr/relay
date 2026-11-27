// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package chunking

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/nfltr/relay/proto/pb"
)

func TestIsUpgrade(t *testing.T) {
	hv := func(v ...string) *pb.HeaderValueList { return &pb.HeaderValueList{HeaderValues: v} }
	for _, tc := range []struct {
		h    map[string]*pb.HeaderValueList
		want bool
	}{
		{map[string]*pb.HeaderValueList{"Connection": hv("Upgrade"), "Upgrade": hv("websocket")}, true},
		{map[string]*pb.HeaderValueList{"Connection": hv("keep-alive, upgrade"), "Upgrade": hv("websocket")}, true},
		{map[string]*pb.HeaderValueList{"Connection": hv("keep-alive"), "Upgrade": hv("websocket")}, false},
		{map[string]*pb.HeaderValueList{"Connection": hv("Upgrade")}, false},
		{nil, false},
	} {
		if got := IsUpgrade(tc.h); got != tc.want {
			t.Errorf("IsUpgrade(%v) = %v, want %v", tc.h, got, tc.want)
		}
	}
}

// TestReadUpgradeChunks: chunk 0 is empty and sent before r has any byte,
// each read follows as it arrives (no look-ahead), and r's end, error or
// not, is an empty last chunk.
func TestReadUpgradeChunks(t *testing.T) {
	for _, end := range []error{io.EOF, errors.New("reset")} {
		pr, pw := io.Pipe()
		ch := ReadUpgradeChunksWithContext(context.Background(), pr)
		if c := <-ch; len(c.Payload) != 0 || c.Last {
			t.Fatalf("chunk 0 = %+v, want empty and not last before any byte", c)
		}
		go func() { _, _ = pw.Write([]byte("frame")) }()
		if c := <-ch; string(c.Payload) != "frame" || c.Last {
			t.Fatalf("chunk 1 = %+v, want the first read alone", c)
		}
		_ = pw.CloseWithError(end)
		if c := <-ch; len(c.Payload) != 0 || !c.Last {
			t.Fatalf("after %v: %+v, want an empty last chunk", end, c)
		}
		if _, ok := <-ch; ok {
			t.Fatal("channel not closed after the last chunk")
		}
	}
}
