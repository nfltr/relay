// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpccodec

import (
	"math/bits"
	"sync"

	"google.golang.org/grpc/mem"
)

// Pool is the buffer pool of the agent's client conn and the relay's server
// (experimental.WithBufferPool / experimental.BufferPool) and of this codec:
// HTTP/2 frames, received messages and marshalled messages.
//
// grpc-go's default pool zeroes a buffer on every Get, and its size classes
// stop at 32 KiB below its 1 MiB one: a 64 KiB TCP tunnel frame took a
// 1 MiB buffer and cleared all of it, on both ends, per frame (13-15% of
// relay and agent CPU in the docker benchmark). This pool
// has a class per power of two from 1 KiB to 1 MiB and does not zero:
// gRPC overwrites every byte it hands out (frames are read in full,
// messages marshalled in full), as with grpc-go's own dirty pool.
// Buffers over 1 MiB are not pooled (see largeMessageCodec).
var Pool mem.BufferPool = &dirtyPool{}

const (
	minPoolShift = 10 // 1 KiB, grpc-go's pooling threshold
	maxPoolShift = 20 // 1 MiB, pooledMessageLimit
)

type dirtyPool struct {
	classes [maxPoolShift - minPoolShift + 1]sync.Pool
}

// class returns the index of the smallest class holding size, or -1.
func class(size int) int {
	s := max(bits.Len(uint(size-1)), minPoolShift)
	if s > maxPoolShift {
		return -1
	}
	return s - minPoolShift
}

func (p *dirtyPool) Get(size int) *[]byte {
	c := class(size)
	if c < 0 {
		b := make([]byte, size)
		return &b
	}
	if b, ok := p.classes[c].Get().(*[]byte); ok {
		*b = (*b)[:size]
		return b
	}
	b := make([]byte, size, 1<<(c+minPoolShift))
	return &b
}

func (p *dirtyPool) Put(b *[]byte) {
	n := cap(*b)
	if n < 1<<minPoolShift || n > 1<<maxPoolShift || n&(n-1) != 0 {
		return // not one of ours
	}
	p.classes[bits.Len(uint(n))-1-minPoolShift].Put(b)
}
