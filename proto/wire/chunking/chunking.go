// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package chunking provides streaming helpers for HTTP proxy payloads that
// exceed the gRPC per-message size limit (default 4 MB).
//
// The core primitive is ReadChunksWithContext, which reads an io.Reader in sized pieces
// and sends each piece to a channel — the "channel pipeline" pattern:
//
// http.Request.Body  → ReadChunksWithContext → chan Chunk → gRPC Send (per chunk)
// http.Response.Body → ReadChunksWithContext → chan Chunk → gRPC Send (per chunk)
//
// The first chunk is sized to fit inside the caller's envelope (headers,
// routing, timestamps, etc.), and subsequent chunks use the full gRPC message
// budget since they carry only minimal metadata.
//
// Chunk metadata is carried in two proto headers:
//   - X-Chunk-Index: 0-based chunk sequence number
//   - X-Chunk-Last:  "true" on the final chunk of a transfer
//
// Non-chunked messages (small payloads that fit in a single gRPC message)
// omit these headers entirely for backward compatibility.
package chunking

import (
	"context"
	"io"
	"maps"
	"strconv"
	"sync"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/protobuf/proto"
)

const (
	HeaderIndex = "X-Chunk-Index"
	HeaderLast  = "X-Chunk-Last"
)

// MaxPayload caps a chunk's payload below the gRPC message limit (8 MiB by
// default). A response is relayed ResponseWindow chunks at a time and its
// first chunk waits for the next to be read (to mark the last one), so the
// chunk size sets both the memory each in-flight body holds on the agent and
// the relay and the time to its first byte; 1 MiB keeps a 4-chunk window
// above 40 MB/s at 100 ms RTT.
const MaxPayload = 1 << 20

// MaxMessageSize is the gRPC message size the wire assumes (8 MiB, the
// relay's grpc.max_message_size default). Chunks are capped at MaxPayload,
// far below it, so a relay configured larger changes nothing here.
const MaxMessageSize = 8 << 20

// chunkBufPool recycles the read buffers (MaxPayload) used by chunk readers,
// reducing GC pressure during sustained transfers.
var chunkBufPool = sync.Pool{
	New: func() any { return make([]byte, MaxPayload) },
}

// PayloadBudget is PayloadBudgetWithin the wire's MaxMessageSize.
// allow:wrapper (the client side, which has no configured limit)
func PayloadBudget(envelope proto.Message) int {
	return PayloadBudgetWithin(envelope, MaxMessageSize)
}

// PayloadBudgetWithin returns the number of payload bytes that fit in a gRPC
// message of at most limit bytes after subtracting the serialized size of
// envelope, at most MaxPayload (a relay passes its configured limit).  envelope
// should be a fully-populated proto message with Payload set to nil.
// The result accounts for the varint length prefix that protobuf adds
// when the Payload field is populated.
func PayloadBudgetWithin(envelope proto.Message, limit int) int {
	overhead := proto.Size(envelope)
	// protobuf adds field tags + varint length prefixes for the Payload
	// bytes field AND changes the parent message's length prefix when the
	// payload is large.  With nested messages (HTTPProxyResponse →
	// HTTPResponse → Payload) the cascading varint growth can exceed a
	// naive 10-byte estimate; 64 bytes provides ample headroom.
	const varintSlack = 64
	return max(min(limit-overhead-varintSlack, MaxPayload), 1)
}

// Chunk holds one piece of a streamed body.
type Chunk struct {
	Payload []byte
	Last    bool // true on the final piece
}

// ReadChunksWithContext reads r in sized pieces and sends each to the returned
// channel with cancellation support.
// firstSize is the max payload for the first chunk (to fit within an envelope
// that carries headers/routing/etc.). restSize is the max payload for every
// subsequent chunk (typically PayloadBudget, MaxPayload, since those messages
// carry only minimal metadata).
//
// The channel is closed after the last piece has been sent.
// Every stream produces exactly one Chunk with Last=true (unless the reader
// is empty, in which case the channel closes with zero sends).
//
// A goroutine performs the reads; it exits when r is exhausted or returns
// a non-EOF error.
//
// For long-lived streaming responses (SSE, NDJSON) use
// ReadChunksStreamingWithContext instead — it forwards data without
// look-ahead buffering.
// If ctx is cancelled while the producer goroutine is blocked on channel send,
// the goroutine exits and closes the output channel.
//
// Memory: the channel is unbuffered and a full chunk is handed over in the
// buffer it was read into, so the producer holds one chunk back (to set
// Last) plus the one it is reading: with the consumer's, three chunk buffers
// per stream. Only a short final read is copied, to its exact size, so a
// small body keeps no chunk-sized buffer and the pooled one is reused.
func ReadChunksWithContext(ctx context.Context, r io.Reader, firstSize, restSize int) <-chan Chunk {
	ch := make(chan Chunk)
	go func() {
		defer close(ch)
		chunkSize := firstSize
		buf := chunkBufPool.Get().([]byte)
		if len(buf) < max(firstSize, restSize) {
			buf = make([]byte, max(firstSize, restSize))
		}
		defer func() { chunkBufPool.Put(buf) }() //nolint:staticcheck // pool reuse is intentional
		var prev []byte                          // hold one chunk back so we can set Last correctly
		for {
			n, err := io.ReadFull(r, buf[:chunkSize])
			if n > 0 {
				var data []byte
				if err == nil { // a full chunk: hand this buffer over, read the next into a new one
					data = buf[:n:n]
					buf = make([]byte, len(buf))
				} else {
					data = make([]byte, n)
					copy(data, buf[:n])
				}
				if prev != nil {
					if !sendChunk(ctx, ch, Chunk{Payload: prev, Last: false}) {
						return
					}
				}
				prev = data
				chunkSize = restSize // subsequent reads use full budget
			}
			if err != nil {
				// EOF / ErrUnexpectedEOF / real error — flush prev as last.
				if prev != nil {
					if !sendChunk(ctx, ch, Chunk{Payload: prev, Last: true}) {
						return
					}
				}
				return
			}
		}
	}()
	return ch
}

// ReadChunksStreamingWithContext reads r and sends each piece to the returned
// channel as
// soon as data is available, without look-ahead buffering. This is critical
// for long-lived streaming responses such as Server-Sent Events (SSE) and
// chunked JSON APIs (NDJSON), where individual frames are much smaller than
// the gRPC message budget and must be forwarded with minimal latency.
//
// Unlike ReadChunksWithContext, this function uses r.Read() (not io.ReadFull)
// and does
// NOT hold one chunk back; each read result is emitted immediately. The
// trade-off is that the Last flag is only set when r.Read() returns data and
// an error (typically EOF) simultaneously. If the reader returns data and nil
// separately, a zero-payload sentinel chunk with Last=true is emitted after
// the final data.
// If ctx is cancelled while the producer goroutine is blocked on channel send,
// the goroutine exits and closes the output channel.
func ReadChunksStreamingWithContext(ctx context.Context, r io.Reader, firstSize, restSize int) <-chan Chunk {
	ch := make(chan Chunk, 2)
	go func() {
		defer close(ch)
		chunkSize := firstSize
		buf := chunkBufPool.Get().([]byte)
		if len(buf) < max(firstSize, restSize) {
			buf = make([]byte, max(firstSize, restSize))
		}
		defer chunkBufPool.Put(buf) //nolint:staticcheck // pool reuse is intentional
		sentAny := false
		for {
			n, err := r.Read(buf[:chunkSize])
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				if err != nil {
					// Data + EOF in same call: this is the final chunk.
					if !sendChunk(ctx, ch, Chunk{Payload: data, Last: true}) {
						return
					}
					return
				}
				if !sendChunk(ctx, ch, Chunk{Payload: data, Last: false}) {
					return
				}
				sentAny = true
				chunkSize = restSize
			}
			if err != nil {
				// EOF with no data — send a termination sentinel so the
				// consumer knows the stream is done.
				if sentAny {
					if !sendChunk(ctx, ch, Chunk{Last: true}) {
						return
					}
				}
				return
			}
		}
	}()
	return ch
}

func sendChunk(ctx context.Context, ch chan<- Chunk, chunk Chunk) bool {
	select {
	case ch <- chunk:
		return true
	case <-ctx.Done():
		return false
	}
}

// ---------------------------------------------------------------------------
// Chunk header helpers
// ---------------------------------------------------------------------------

// SetChunkHeaders writes chunk index and last-flag into a proto header map.
func SetChunkHeaders(h map[string]*pb.HeaderValueList, index int, last bool) {
	h[HeaderIndex] = &pb.HeaderValueList{HeaderValues: []string{strconv.Itoa(index)}}
	if last {
		h[HeaderLast] = &pb.HeaderValueList{HeaderValues: []string{"true"}}
	}
}

// IsChunked reports whether the message carries chunk headers.
func IsChunked(h map[string]*pb.HeaderValueList) bool {
	_, ok := h[HeaderIndex]
	return ok
}

// GetChunkIndex returns the 0-based chunk index (0 if absent).
func GetChunkIndex(h map[string]*pb.HeaderValueList) int {
	v, ok := h[HeaderIndex]
	if !ok || len(v.HeaderValues) == 0 {
		return 0
	}
	i, _ := strconv.Atoi(v.HeaderValues[0])
	return i
}

// IsLastChunk reports whether this is the final chunk of a transfer.
func IsLastChunk(h map[string]*pb.HeaderValueList) bool {
	v, ok := h[HeaderLast]
	return ok && len(v.HeaderValues) > 0 && v.HeaderValues[0] == "true"
}

// StripHeaders removes chunk metadata from a header map.
func StripHeaders(h map[string]*pb.HeaderValueList) {
	delete(h, HeaderIndex)
	delete(h, HeaderLast)
}

// CopyHeaders returns a shallow copy of a proto header map.
func CopyHeaders(src map[string]*pb.HeaderValueList) map[string]*pb.HeaderValueList {
	dst := make(map[string]*pb.HeaderValueList, len(src))
	maps.Copy(dst, src)
	return dst
}
