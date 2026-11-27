// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"errors"
	"testing"
	"time"
)

func TestSend(t *testing.T) {
	ch := make(chan int, 1)
	done := make(chan struct{})
	if err := Send(ch, 1, done, 0); err != nil {
		t.Fatalf("room: %v", err)
	}
	if err := Send(ch, 2, done, 0); !errors.Is(err, ErrStalled) {
		t.Fatalf("full, no bound: %v, want ErrStalled", err)
	}
	start := time.Now()
	if err := Send(ch, 2, done, 20*time.Millisecond); !errors.Is(err, ErrStalled) || time.Since(start) < 20*time.Millisecond {
		t.Fatalf("full, bound: %v after %v, want ErrStalled after the bound", err, time.Since(start))
	}
	go func() { time.Sleep(10 * time.Millisecond); <-ch }()
	if err := Send(ch, 3, done, time.Minute); err != nil {
		t.Fatalf("a take ends the wait: %v", err)
	}
	close(done)
	if err := Send(ch, 4, done, time.Minute); !errors.Is(err, ErrEnded) {
		t.Fatalf("consumer ended: %v, want ErrEnded", err)
	}
}
