// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package chunking

import (
	"context"
	"errors"
	"io"
	"strconv"
	"sync"

	"github.com/nfltr/relay/proto/pb"
)

// ErrUploadWindow means the relay sent more than UploadWindow unacknowledged
// chunks of one request body.
var ErrUploadWindow = errors.New("relay exceeded the upload window")

// Upload is one request body streamed from an agent's receive loop to its
// local request. The receive loop hands each chunk over with Deliver, which
// never blocks: the relay keeps at most UploadWindow chunks unacknowledged,
// and the reader acks a chunk once it has read all of it. The agent holds
// at most UploadWindow chunks of the body instead of all of it.
type Upload struct {
	ctx    context.Context
	ack    func(index int)
	chunks chan []byte

	mu     sync.Mutex
	ended  bool // last chunk delivered, or the window broken
	closed bool // the reader is done: later chunks are dropped and acked
	err    error
	acked  int

	cur  []byte
	held bool // cur is a chunk not yet acked
}

// StreamedContentLength is the request's Content-Length header for a body
// streamed to the backend, or -1 (unknown: chunked) without a valid one.
func StreamedContentLength(h map[string]*pb.HeaderValueList) int64 {
	if v, ok := h["Content-Length"]; ok && len(v.GetHeaderValues()) > 0 {
		if n, err := strconv.ParseInt(v.GetHeaderValues()[0], 10, 64); err == nil && n >= 0 {
			return n
		}
	}
	return -1
}

// NewUpload starts a body whose chunks ack sends to the relay; Read fails
// once ctx ends.
func NewUpload(ctx context.Context, ack func(index int)) *Upload {
	return &Upload{ctx: ctx, ack: ack, chunks: make(chan []byte, UploadWindow)}
}

// Deliver hands the next chunk over and reports whether the body is
// complete, so the receive loop can forget it.
func (u *Upload) Deliver(payload []byte, last bool) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case u.ended:
		return true
	case u.closed:
		u.ackLocked()
	default:
		select {
		case u.chunks <- payload:
		default:
			u.err, last = ErrUploadWindow, true
		}
	}
	if last {
		u.ended = true
		close(u.chunks)
	}
	return last
}

func (u *Upload) ackLocked() {
	u.ack(u.acked)
	u.acked++
}

func (u *Upload) Read(p []byte) (int, error) {
	for len(u.cur) == 0 {
		if u.held {
			u.mu.Lock()
			u.ackLocked()
			u.mu.Unlock()
			u.held = false
		}
		select {
		case c, ok := <-u.chunks:
			if !ok {
				u.mu.Lock()
				defer u.mu.Unlock()
				if u.err != nil {
					return 0, u.err
				}
				return 0, io.EOF
			}
			u.cur, u.held = c, true
		case <-u.ctx.Done():
			return 0, u.ctx.Err()
		}
	}
	n := copy(p, u.cur)
	u.cur = u.cur[n:]
	return n, nil
}

// Close drops what the reader left: the chunks already delivered and any
// still to come are acked, so the relay is never left waiting. It may run
// concurrently with Read (net/http closes a request body asynchronously), so
// it leaves the reader's current chunk alone: the window just has one slot
// fewer for the rest of the body.
func (u *Upload) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	for {
		select {
		case _, ok := <-u.chunks:
			if !ok {
				return nil
			}
			u.ackLocked()
		default:
			return nil
		}
	}
}
