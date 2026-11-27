// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package chunking

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// relaySim sends chunks the way the relay does: chunk i only once
// i-UploadWindow chunks are acked.
func relaySim(u *Upload, chunks [][]byte, acks <-chan int) {
	for i, c := range chunks {
		if i >= UploadWindow {
			<-acks
		}
		u.Deliver(c, i == len(chunks)-1)
	}
}

func TestUploadStreamsWithinTheWindow(t *testing.T) {
	var chunks [][]byte
	var want bytes.Buffer
	for i := range 20 {
		c := bytes.Repeat([]byte(strconv.Itoa(i%10)), 1000+i)
		chunks = append(chunks, c)
		want.Write(c)
	}
	acks := make(chan int, len(chunks))
	u := NewUpload(context.Background(), func(i int) { acks <- i })
	go relaySim(u, chunks, acks)
	got, err := io.ReadAll(u)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("body: %d bytes, want %d", len(got), want.Len())
	}
	if u.err != nil {
		t.Fatalf("window broken: %v", u.err)
	}
}

// A reader that stops early (a backend answering before the whole body)
// must not leave the relay waiting for acks.
func TestUploadCloseAcksWhatIsLeft(t *testing.T) {
	chunks := make([][]byte, 12)
	for i := range chunks {
		chunks[i] = []byte("chunk")
	}
	acks := make(chan int, len(chunks))
	var n atomic.Int32
	u := NewUpload(context.Background(), func(i int) { n.Add(1); acks <- i })
	done := make(chan struct{})
	go func() { relaySim(u, chunks, acks); close(done) }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(u, buf); err != nil {
		t.Fatal(err)
	}
	_ = u.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("relay stuck after the reader closed (%d acks)", n.Load())
	}
}

func TestUploadRejectsABrokenWindow(t *testing.T) {
	u := NewUpload(context.Background(), func(int) {})
	for range UploadWindow {
		if u.Deliver([]byte("x"), false) {
			t.Fatal("ended inside the window")
		}
	}
	if !u.Deliver([]byte("x"), false) {
		t.Fatal("a chunk past the window was accepted")
	}
	if _, err := io.ReadAll(u); !errors.Is(err, ErrUploadWindow) {
		t.Fatalf("read err = %v, want %v", err, ErrUploadWindow)
	}
}

func TestUploadReadEndsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	u := NewUpload(ctx, func(int) {})
	u.Deliver([]byte("a"), false)
	cancel()
	if _, err := io.ReadAll(u); !errors.Is(err, context.Canceled) {
		t.Fatalf("read err = %v, want context.Canceled", err)
	}
}
