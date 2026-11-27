// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package chunking

import (
	"context"
	"io"
	"strings"

	"github.com/nfltr/relay/proto/pb"
)

// A protocol upgrade (WebSocket: a request with "Connection: Upgrade" and an
// Upgrade header, answered 101 Switching Protocols) rides one transaction of
// the HTTP tunnel as two streams of chunks under the usual windows:
//
//   - relay → agent: the request is chunk 0 of a streamed upload (not last,
//     HeaderUploadAcks), sent at once; the visitor's bytes after the switch
//     are its further chunks, a last chunk when the visitor's side ends.
//   - agent → relay: the backend's 101 is chunk 0 of the response (not
//     last), sent at once; the backend's bytes are its further chunks, a
//     last chunk when the backend's side ends.
//
// Both sides read with ReadUpgradeChunksWithContext. An agent whose backend
// does not switch answers as for any request; the upload is then dropped.

// UpgradeChunkSize is the largest chunk ReadUpgradeChunksWithContext sends:
// an upgraded connection carries small interactive frames, and each side
// holds one buffer of this size per connection.
const UpgradeChunkSize = 64 << 10

// IsUpgrade reports whether a relayed request asks for a protocol upgrade.
func IsUpgrade(h map[string]*pb.HeaderValueList) bool {
	if len(h["Upgrade"].GetHeaderValues()) == 0 {
		return false
	}
	for _, v := range h["Connection"].GetHeaderValues() {
		for tok := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// ReadUpgradeChunksWithContext sends an empty chunk at once (chunk 0, which
// carries the request or the 101), then each read of r as it arrives, then
// an empty last chunk when r ends, with an error or not.
func ReadUpgradeChunksWithContext(ctx context.Context, r io.Reader) <-chan Chunk {
	ch := make(chan Chunk, 2)
	go func() {
		defer close(ch)
		if !sendChunk(ctx, ch, Chunk{}) {
			return
		}
		buf := make([]byte, UpgradeChunkSize)
		for {
			n, err := r.Read(buf)
			if n > 0 && !sendChunk(ctx, ch, Chunk{Payload: append([]byte(nil), buf[:n]...)}) {
				return
			}
			if err != nil {
				sendChunk(ctx, ch, Chunk{Last: true})
				return
			}
		}
	}()
	return ch
}
