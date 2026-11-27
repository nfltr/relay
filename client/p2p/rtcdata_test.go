// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"bytes"
	"crypto/rand"
	"sync/atomic"
	"testing"
	"time"
)

func TestChunkWriterBackPressure(t *testing.T) {
	const chunk, high = 1000, 10000
	var queued atomic.Int64
	var peak int64
	low := make(chan struct{}, 1)
	done := make(chan struct{})
	defer close(done)
	go func() { // the network drains the queue and signals low water
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
			}
			if q := queued.Load(); q > 0 {
				queued.Add(-min(q, 3000))
				select {
				case low <- struct{}{}:
				default:
				}
			}
		}
	}()
	var sent bytes.Buffer
	w := &chunkWriter{
		send: func(b []byte) error {
			if len(b) > chunk {
				t.Errorf("message of %d bytes, chunk is %d", len(b), chunk)
			}
			sent.Write(b)
			if q := queued.Add(int64(len(b))); q > peak {
				peak = q
			}
			return nil
		},
		buffered: func() uint64 { return uint64(queued.Load()) },
		low:      low,
		done:     make(chan struct{}),
		chunk:    chunk,
		high:     high,
	}
	data := make([]byte, 500_000)
	_, _ = rand.Read(data)
	if n, err := w.Write(data); err != nil || n != len(data) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if !bytes.Equal(sent.Bytes(), data) {
		t.Fatal("chunks do not reassemble the input")
	}
	if peak > high+chunk {
		t.Fatalf("queue peaked at %d bytes, bound is %d", peak, high+chunk)
	}
	close(w.done)
	queued.Store(high + 1)
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("a write on a closed conn must fail, not wait")
	}
}
