// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package bytequeue

import (
	"errors"
	"testing"
	"time"
)

// TestPushWithin: a full queue whose reader takes nothing fails the push
// after the stall bound; one whose reader keeps taking, however slowly,
// never does; a closed one reports ErrClosed.
func TestPushWithin(t *testing.T) {
	q := New(4)
	if err := q.PushWithin([]byte("abcd"), time.Second); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := q.PushWithin([]byte("x"), 100*time.Millisecond); !errors.Is(err, ErrStalled) {
		t.Fatalf("stuck reader: %v", err)
	}
	if d := time.Since(start); d < 100*time.Millisecond {
		t.Fatalf("gave up after %v, bound 100ms", d)
	}

	// A paced reader: each push waits for a pop, well past the bound in
	// all, never past it at once.
	go func() {
		for range 8 {
			time.Sleep(50 * time.Millisecond)
			q.Pop()
		}
	}()
	for i := range 8 {
		if err := q.PushWithin([]byte("abcd"), 500*time.Millisecond); err != nil {
			t.Fatalf("push %d beside a paced reader: %v", i, err)
		}
	}

	q.Close()
	if err := q.PushWithin([]byte("x"), time.Second); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
}
