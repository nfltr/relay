// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package chunking

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/protobuf/proto"
)

// testChunkSize is used throughout tests as a consistent chunk size.
const testChunkSize = MaxMessageSize

// ---------------------------------------------------------------------------
// ReadChunks tests
// ---------------------------------------------------------------------------

func TestReadChunks_Empty(t *testing.T) {
	ch := ReadChunksWithContext(context.Background(), bytes.NewReader(nil), testChunkSize, testChunkSize)
	chunks := drain(ch)
	if len(chunks) != 0 {
		t.Fatalf("expected 0 chunks for empty reader, got %d", len(chunks))
	}
}

func TestReadChunks_SmallPayload(t *testing.T) {
	data := []byte("hello world")
	ch := ReadChunksWithContext(context.Background(), bytes.NewReader(data), testChunkSize, testChunkSize)
	chunks := drain(ch)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if !chunks[0].Last {
		t.Error("single chunk should have Last=true")
	}
	if !bytes.Equal(chunks[0].Payload, data) {
		t.Errorf("payload mismatch: got %q", chunks[0].Payload)
	}
}

func TestReadChunks_ExactlyChunkSize(t *testing.T) {
	data := make([]byte, testChunkSize)
	rand.Read(data)
	ch := ReadChunksWithContext(context.Background(), bytes.NewReader(data), testChunkSize, testChunkSize)
	chunks := drain(ch)
	// io.ReadFull fills the full buffer, gets EOF on the next read → 1 chunk
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for exactly chunkSize, got %d", len(chunks))
	}
	if !chunks[0].Last {
		t.Error("should be last chunk")
	}
	if !bytes.Equal(chunks[0].Payload, data) {
		t.Error("payload mismatch")
	}
}

func TestReadChunks_MultipleChunks(t *testing.T) {
	// 3 full chunks + 100 bytes remainder = 4 chunks total
	size := testChunkSize*3 + 100
	data := make([]byte, size)
	rand.Read(data)

	ch := ReadChunksWithContext(context.Background(), bytes.NewReader(data), testChunkSize, testChunkSize)
	chunks := drain(ch)

	if len(chunks) != 4 {
		t.Fatalf("expected 4 chunks, got %d", len(chunks))
	}

	// Only the last chunk should have Last=true
	for i, c := range chunks {
		if i < len(chunks)-1 && c.Last {
			t.Errorf("chunk %d should not be last", i)
		}
	}
	if !chunks[len(chunks)-1].Last {
		t.Error("final chunk should have Last=true")
	}

	// Concatenation should equal original data
	var assembled []byte
	for _, c := range chunks {
		assembled = append(assembled, c.Payload...)
	}
	if !bytes.Equal(assembled, data) {
		t.Error("assembled data does not match original")
	}
}

func TestReadChunks_LargeRoundTrip(t *testing.T) {
	// 10 MB random data
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	rand.Read(data)

	ch := ReadChunksWithContext(context.Background(), bytes.NewReader(data), testChunkSize, testChunkSize)
	var assembled []byte
	count := 0
	lastSeen := false
	for chunk := range ch {
		count++
		assembled = append(assembled, chunk.Payload...)
		if chunk.Last {
			lastSeen = true
		}
	}
	if !lastSeen {
		t.Error("never saw Last=true")
	}
	if !bytes.Equal(assembled, data) {
		t.Error("round-trip data mismatch")
	}
	expectedChunks := (size + testChunkSize - 1) / testChunkSize
	if count != expectedChunks {
		t.Errorf("expected %d chunks, got %d", expectedChunks, count)
	}
}

func TestReadChunks_StreamFromPipe(t *testing.T) {
	pr, pw := io.Pipe()
	data := bytes.Repeat([]byte("A"), testChunkSize+500)

	go func() {
		// Write in small drips to simulate streaming
		for i := 0; i < len(data); i += 1000 {
			end := min(i+1000, len(data))
			_, _ = pw.Write(data[i:end])
		}
		_ = pw.Close()
	}()

	ch := ReadChunksWithContext(context.Background(), pr, testChunkSize, testChunkSize)
	var assembled []byte
	for chunk := range ch {
		assembled = append(assembled, chunk.Payload...)
	}
	if !bytes.Equal(assembled, data) {
		t.Error("pipe stream data mismatch")
	}
}

// TestReadChunks_DifferentFirstSize verifies that the first chunk uses
// firstSize and subsequent chunks use restSize.
func TestReadChunks_DifferentFirstSize(t *testing.T) {
	firstSize := 1000
	restSize := 3000
	// Data: 1000 + 3000 + 3000 + 500 = 7500 bytes → 4 chunks
	size := firstSize + restSize*2 + 500
	data := make([]byte, size)
	rand.Read(data)

	ch := ReadChunksWithContext(context.Background(), bytes.NewReader(data), firstSize, restSize)
	chunks := drain(ch)

	if len(chunks) != 4 {
		t.Fatalf("expected 4 chunks, got %d", len(chunks))
	}
	if len(chunks[0].Payload) != firstSize {
		t.Errorf("first chunk: expected %d bytes, got %d", firstSize, len(chunks[0].Payload))
	}
	if len(chunks[1].Payload) != restSize {
		t.Errorf("second chunk: expected %d bytes, got %d", restSize, len(chunks[1].Payload))
	}
	if len(chunks[2].Payload) != restSize {
		t.Errorf("third chunk: expected %d bytes, got %d", restSize, len(chunks[2].Payload))
	}
	if len(chunks[3].Payload) != 500 {
		t.Errorf("fourth chunk: expected 500 bytes, got %d", len(chunks[3].Payload))
	}
	if !chunks[3].Last {
		t.Error("last chunk should have Last=true")
	}

	var assembled []byte
	for _, c := range chunks {
		assembled = append(assembled, c.Payload...)
	}
	if !bytes.Equal(assembled, data) {
		t.Error("assembled data mismatch")
	}
}

// TestReadChunks_SmallFirstLargeRest verifies a small first budget
// followed by large rest budgets.
func TestReadChunks_SmallFirstLargeRest(t *testing.T) {
	firstSize := 100
	restSize := MaxMessageSize
	// 100 bytes first, then one full-size chunk, then remainder
	size := 100 + MaxMessageSize + 500
	data := make([]byte, size)
	rand.Read(data)

	ch := ReadChunksWithContext(context.Background(), bytes.NewReader(data), firstSize, restSize)
	chunks := drain(ch)

	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
	if len(chunks[0].Payload) != firstSize {
		t.Errorf("first chunk: expected %d bytes, got %d", firstSize, len(chunks[0].Payload))
	}
	if len(chunks[1].Payload) != MaxMessageSize {
		t.Errorf("second chunk: expected %d bytes, got %d", MaxMessageSize, len(chunks[1].Payload))
	}
	if len(chunks[2].Payload) != 500 {
		t.Errorf("third chunk: expected %d bytes, got %d", 500, len(chunks[2].Payload))
	}

	var assembled []byte
	for _, c := range chunks {
		assembled = append(assembled, c.Payload...)
	}
	if !bytes.Equal(assembled, data) {
		t.Error("assembled data mismatch")
	}
}

// TestPayloadBudget verifies that PayloadBudget returns a reasonable value.
func TestPayloadBudget(t *testing.T) {
	envelope := &pb.HTTPProxyRequest{
		Request: &pb.HTTPRequest{
			TransactionId: "txn-12345678-1234-1234-1234-123456789012",
			Headers:       make(map[string]*pb.HeaderValueList),
			Method:        "POST",
			Url:           "/api/v2/some/resource/path",
		},
		Timestamps: &pb.Timestamps{
			RequestAtHttpServer: 1000,
		},
		Routing: &pb.RoutingInfo{
			AgentId: "my-agent-01",
		},
	}
	// A typical envelope (~200 bytes) leaves the gRPC limit far above
	// MaxPayload: the chunk is MaxPayload, which bounds the memory a body in
	// flight holds and its time to first byte.
	if budget := PayloadBudget(envelope); budget != MaxPayload {
		t.Fatalf("budget = %d, want MaxPayload %d", budget, MaxPayload)
	}
	// A tight gRPC limit still wins: the chunk and its envelope fit in it.
	if budget := PayloadBudgetWithin(envelope, 64*1024); budget <= 0 || budget+proto.Size(envelope) > 64*1024 {
		t.Fatalf("budget = %d with a 64 KiB gRPC limit, want a positive payload that fits", budget)
	}
}

// ---------------------------------------------------------------------------
// Header helper tests
// ---------------------------------------------------------------------------

func TestSetChunkHeaders_NotLast(t *testing.T) {
	h := make(map[string]*pb.HeaderValueList)
	SetChunkHeaders(h, 2, false)

	if h[HeaderIndex].HeaderValues[0] != "2" {
		t.Errorf("expected index 2, got %s", h[HeaderIndex].HeaderValues[0])
	}
	if _, ok := h[HeaderLast]; ok {
		t.Error("HeaderLast should not be set for non-last chunk")
	}
}

func TestSetChunkHeaders_Last(t *testing.T) {
	h := make(map[string]*pb.HeaderValueList)
	SetChunkHeaders(h, 5, true)

	if h[HeaderIndex].HeaderValues[0] != "5" {
		t.Errorf("expected index 5, got %s", h[HeaderIndex].HeaderValues[0])
	}
	if h[HeaderLast].HeaderValues[0] != "true" {
		t.Error("HeaderLast should be 'true'")
	}
}

func TestIsChunked(t *testing.T) {
	h := make(map[string]*pb.HeaderValueList)
	if IsChunked(h) {
		t.Error("empty headers should not be chunked")
	}
	SetChunkHeaders(h, 0, false)
	if !IsChunked(h) {
		t.Error("headers with X-Chunk-Index should be chunked")
	}
}

func TestGetChunkIndex(t *testing.T) {
	h := make(map[string]*pb.HeaderValueList)
	if GetChunkIndex(h) != 0 {
		t.Error("absent index should return 0")
	}
	SetChunkHeaders(h, 7, false)
	if GetChunkIndex(h) != 7 {
		t.Errorf("expected 7, got %d", GetChunkIndex(h))
	}
}

func TestIsLastChunk(t *testing.T) {
	h := make(map[string]*pb.HeaderValueList)
	if IsLastChunk(h) {
		t.Error("empty headers should not be last")
	}
	SetChunkHeaders(h, 0, true)
	if !IsLastChunk(h) {
		t.Error("should be last")
	}
}

func TestStripHeaders(t *testing.T) {
	h := make(map[string]*pb.HeaderValueList)
	SetChunkHeaders(h, 3, true)
	h["Content-Type"] = &pb.HeaderValueList{HeaderValues: []string{"text/html"}}

	StripHeaders(h)
	if _, ok := h[HeaderIndex]; ok {
		t.Error("HeaderIndex should be stripped")
	}
	if _, ok := h[HeaderLast]; ok {
		t.Error("HeaderLast should be stripped")
	}
	if _, ok := h["Content-Type"]; !ok {
		t.Error("Content-Type should be preserved")
	}
}

func TestCopyHeaders(t *testing.T) {
	src := map[string]*pb.HeaderValueList{
		"A": {HeaderValues: []string{"1"}},
		"B": {HeaderValues: []string{"2", "3"}},
	}
	dst := CopyHeaders(src)
	if len(dst) != 2 {
		t.Errorf("expected 2 headers, got %d", len(dst))
	}
	// Modifying dst should not affect src
	dst["C"] = &pb.HeaderValueList{HeaderValues: []string{"new"}}
	if _, ok := src["C"]; ok {
		t.Error("copy should be independent")
	}
}

// ---------------------------------------------------------------------------
// End-to-end: simulate agent response chunking → server reassembly
// ---------------------------------------------------------------------------

func TestEndToEnd_AgentChunkingServerReassembly(t *testing.T) {
	// Simulate: agent reads a 7 MB response body, chunks it, server reassembles.
	size := 7 * 1024 * 1024
	body := make([]byte, size)
	rand.Read(body)

	// --- Agent side: ReadChunks the body → build proto messages ---
	chunkCh := ReadChunksWithContext(context.Background(), bytes.NewReader(body), testChunkSize, testChunkSize)
	var messages []*pb.HTTPProxyResponse
	index := 0
	for chunk := range chunkCh {
		msg := &pb.HTTPProxyResponse{
			Response: &pb.HTTPResponse{
				TransactionId: "txn-1",
				Headers:       make(map[string]*pb.HeaderValueList),
				Payload:       chunk.Payload,
			},
		}
		if index == 0 {
			msg.Response.StatusCode = 200
			msg.Response.Headers["Content-Type"] = &pb.HeaderValueList{
				HeaderValues: []string{"application/octet-stream"},
			}
		}
		SetChunkHeaders(msg.Response.Headers, index, chunk.Last)
		messages = append(messages, msg)
		index++
	}

	t.Logf("Agent produced %d chunks for %d bytes", len(messages), size)

	// --- Server side: read first message, stream rest ---
	first := messages[0]
	if !IsChunked(first.Response.Headers) {
		t.Fatal("first message should be chunked")
	}
	StripHeaders(first.Response.Headers)

	var assembled []byte
	assembled = append(assembled, first.Response.Payload...)

	for i := 1; i < len(messages); i++ {
		msg := messages[i]
		assembled = append(assembled, msg.Response.Payload...)
		if IsLastChunk(msg.Response.Headers) {
			if i != len(messages)-1 {
				t.Errorf("last chunk at %d but expected at %d", i, len(messages)-1)
			}
			break
		}
	}

	if !bytes.Equal(assembled, body) {
		t.Error("reassembled data does not match original body")
	}
}

// ---------------------------------------------------------------------------
// End-to-end: simulate server request chunking → agent reassembly
// ---------------------------------------------------------------------------

func TestEndToEnd_ServerChunkingAgentReassembly(t *testing.T) {
	// Simulate: server chunks a 5 MB upload body, agent reassembles via pipe.
	size := 5 * 1024 * 1024
	body := make([]byte, size)
	rand.Read(body)

	// --- Server side: ReadChunks the body → build proto messages ---
	chunkCh := ReadChunksWithContext(context.Background(), bytes.NewReader(body), testChunkSize, testChunkSize)
	var messages []*pb.HTTPProxyRequest
	index := 0
	for chunk := range chunkCh {
		msg := &pb.HTTPProxyRequest{
			Request: &pb.HTTPRequest{
				TransactionId: "txn-upload",
				Headers:       make(map[string]*pb.HeaderValueList),
				Payload:       chunk.Payload,
			},
		}
		if index == 0 {
			msg.Request.Method = "POST"
			msg.Request.Url = "/upload"
		}
		SetChunkHeaders(msg.Request.Headers, index, chunk.Last)
		messages = append(messages, msg)
		index++
	}

	t.Logf("Server produced %d chunks for %d bytes", len(messages), size)

	// --- Agent side: pipe reassembly ---
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close() //nolint:errcheck
		for _, msg := range messages {
			_, _ = pw.Write(msg.Request.Payload)
		}
	}()

	assembled, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(assembled, body) {
		t.Error("pipe-reassembled data does not match original body")
	}
}

// ---------------------------------------------------------------------------
// Edge case: payload exactly at boundary multiples
// ---------------------------------------------------------------------------

func TestReadChunks_BoundaryMultiples(t *testing.T) {
	for _, mult := range []int{1, 2, 3} {
		size := testChunkSize * mult
		data := make([]byte, size)
		rand.Read(data)
		ch := ReadChunksWithContext(context.Background(), bytes.NewReader(data), testChunkSize, testChunkSize)
		chunks := drain(ch)

		if len(chunks) != mult {
			t.Errorf("mult=%d: expected %d chunks, got %d", mult, mult, len(chunks))
		}
		var assembled []byte
		for _, c := range chunks {
			assembled = append(assembled, c.Payload...)
		}
		if !bytes.Equal(assembled, data) {
			t.Errorf("mult=%d: data mismatch", mult)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkReadChunks_10MB(b *testing.B) {
	data := make([]byte, 10*1024*1024)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := ReadChunksWithContext(context.Background(), bytes.NewReader(data), testChunkSize, testChunkSize)
		for range ch {
		}
	}
}

func BenchmarkReadChunks_100MB(b *testing.B) {
	data := make([]byte, 100*1024*1024)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := ReadChunksWithContext(context.Background(), strings.NewReader(string(data)), testChunkSize, testChunkSize)
		for range ch {
		}
	}
}

// TestReadChunksStreaming_SSE_LowLatency verifies that small writes (SSE
// events, NDJSON lines) are forwarded promptly without buffering up to
// chunkSize. ReadChunksStreaming emits each read result immediately.
func TestReadChunksStreaming_SSE_LowLatency(t *testing.T) {
	pr, pw := io.Pipe()

	events := []string{
		"data: {\"id\":1}\n\n",
		"data: {\"id\":2}\n\n",
		"data: {\"id\":3}\n\n",
	}

	ch := ReadChunksStreamingWithContext(context.Background(), pr, testChunkSize, testChunkSize)

	// Write SSE events one at a time; each should arrive as its own chunk
	// within a reasonable timeout (not blocking for 4MB).
	go func() {
		for _, ev := range events {
			_, _ = pw.Write([]byte(ev))
		}
		_ = pw.Close()
	}()

	var assembled []byte
	count := 0
	for chunk := range ch {
		assembled = append(assembled, chunk.Payload...)
		count++
	}
	expected := strings.Join(events, "")
	if string(assembled) != expected {
		t.Errorf("assembled data mismatch:\n got: %q\nwant: %q", assembled, expected)
	}
	// With ReadChunksStreaming on a pipe, we expect >= len(events) chunks
	// (one per write + one sentinel). The key assertion: we MUST get more
	// than 1 chunk, proving data wasn't buffered waiting for 4MB.
	if count < 2 {
		t.Errorf("expected multiple chunks for small SSE events, got %d (data was buffered)", count)
	}
}

// TestReadChunksStreaming_SSE_TimedDelivery verifies that an SSE event
// written to a pipe is received on the chunk channel promptly (within
// 100ms), not blocked waiting for a 4MB buffer fill.
func TestReadChunksStreaming_SSE_TimedDelivery(t *testing.T) {
	pr, pw := io.Pipe()
	ch := ReadChunksStreamingWithContext(context.Background(), pr, testChunkSize, testChunkSize)

	event := []byte("data: hello\n\n")

	go func() {
		_, _ = pw.Write(event)
		// Don't close yet — reader shouldn't need EOF to emit the chunk.
	}()

	select {
	case chunk := <-ch:
		if !bytes.Equal(chunk.Payload, event) {
			t.Errorf("payload mismatch: got %q, want %q", chunk.Payload, event)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("SSE event not delivered within 100ms — ReadChunksStreaming is blocking on buffer fill")
	}
	_ = pw.Close()
	// Drain remaining chunks.
	for range ch {
	}
}

// TestReadChunksStreaming_SmallPayload verifies that a small complete payload
// streams correctly, producing data + sentinel chunks.
func TestReadChunksStreaming_SmallPayload(t *testing.T) {
	data := []byte("hello world")
	ch := ReadChunksStreamingWithContext(context.Background(), bytes.NewReader(data), testChunkSize, testChunkSize)
	chunks := drain(ch)
	// bytes.NewReader returns n>0,nil then 0,EOF → 2 chunks (data + sentinel)
	if len(chunks) < 1 {
		t.Fatal("expected at least 1 chunk")
	}
	// Last chunk must have Last=true
	if !chunks[len(chunks)-1].Last {
		t.Error("final chunk should have Last=true")
	}
	// Assembled data must match (excluding zero-payload sentinel)
	var assembled []byte
	for _, c := range chunks {
		assembled = append(assembled, c.Payload...)
	}
	if !bytes.Equal(assembled, data) {
		t.Errorf("payload mismatch: got %q", assembled)
	}
}

// TestReadChunksStreaming_LargeRoundTrip verifies data integrity for large
// payloads through the streaming chunker.
func TestReadChunksStreaming_LargeRoundTrip(t *testing.T) {
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	rand.Read(data)

	ch := ReadChunksStreamingWithContext(context.Background(), bytes.NewReader(data), testChunkSize, testChunkSize)
	var assembled []byte
	lastSeen := false
	for chunk := range ch {
		assembled = append(assembled, chunk.Payload...)
		if chunk.Last {
			lastSeen = true
		}
	}
	if !lastSeen {
		t.Error("never saw Last=true")
	}
	if !bytes.Equal(assembled, data) {
		t.Error("round-trip data mismatch")
	}
}

func TestReadChunksWithContext_CancelWhileSendBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		data := bytes.Repeat([]byte("A"), testChunkSize*6)
		ch := ReadChunksWithContext(ctx, bytes.NewReader(data), testChunkSize, testChunkSize)

		// Allow producer to fill the small output buffer and block on send.
		time.Sleep(20 * time.Millisecond)
		cancel()

		done := make(chan struct{})
		go func() {
			for range ch {
			}
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("ReadChunksWithContext did not close channel after cancellation")
		}
	})
}

func TestReadChunksStreamingWithContext_CancelWhileSendBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		data := bytes.Repeat([]byte("B"), testChunkSize*6)
		ch := ReadChunksStreamingWithContext(ctx, bytes.NewReader(data), testChunkSize, testChunkSize)

		// Allow producer to fill the small output buffer and block on send.
		time.Sleep(20 * time.Millisecond)
		cancel()

		done := make(chan struct{})
		go func() {
			for range ch {
			}
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("ReadChunksStreamingWithContext did not close channel after cancellation")
		}
	})
}

// drain collects all chunks from a channel.
func drain(ch <-chan Chunk) []Chunk {
	var out []Chunk
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// countingZeros is an endless body that counts the bytes read from it.
type countingZeros struct{ n int }

func (c *countingZeros) Read(p []byte) (int, error) {
	clear(p)
	c.n += len(p)
	return len(p), nil
}

// TestReadChunks_BoundedReadAhead guards the reader's memory: while the
// consumer holds a chunk (waiting for the relay's ack or on gRPC flow
// control) the producer reads at most two chunks past it, the one held back
// to set Last and the next. Each read-ahead chunk is a chunk-sized buffer (up
// to grpc.max_message_size, 8 MiB), and a deeper pipeline was most of the
// agent's live heap on a large download.
// allow:wrapper — the body runs in a synctest bubble.
func TestReadChunks_BoundedReadAhead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const size = 1 << 10
		body := &countingZeros{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ch := ReadChunksWithContext(ctx, body, size, size)
		synctest.Wait()
		if body.n > 2*size {
			t.Fatalf("before the first receive the reader read %d chunks, want at most 2", body.n/size)
		}
		<-ch // the consumer now holds chunk 0
		synctest.Wait()
		if body.n > 3*size {
			t.Fatalf("with the consumer holding chunk 0 the reader read %d chunks, want at most 3", body.n/size)
		}
	})
}

// TestReadChunks_SmallBodyExactSize: a body shorter than a chunk is copied
// to its own size, so a small response does not keep a chunk-sized buffer.
func TestReadChunks_SmallBodyExactSize(t *testing.T) {
	chunks := drain(ReadChunksWithContext(context.Background(), strings.NewReader("hello"), testChunkSize, testChunkSize))
	if len(chunks) != 1 || cap(chunks[0].Payload) != 5 {
		t.Fatalf("got %d chunks, cap %d; want one chunk of cap 5", len(chunks), cap(chunks[0].Payload))
	}
}
