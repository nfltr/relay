// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"testing"
	"time"
)

func TestReconnectBackoff_StartsAtBase(t *testing.T) {
	rb := NewReconnectBackoff(DefaultReconnectBase, WithReconnectMax(DefaultReconnectMax))
	rb.randInt63n = func(n int64) int64 { return 0 }

	got := rb.DelayAfterFailure()
	if got < DefaultReconnectBase || got > DefaultReconnectBase+DefaultReconnectBase/4 {
		t.Fatalf("first delay = %s; want [%s, %s]", got, DefaultReconnectBase, DefaultReconnectBase+DefaultReconnectBase/4)
	}
	if got != DefaultReconnectBase {
		t.Fatalf("with zero jitter, first delay = %s; want %s", got, DefaultReconnectBase)
	}
}

func TestReconnectBackoff_DoublesOnRepeatedFailures(t *testing.T) {
	rb := NewReconnectBackoff(DefaultReconnectBase, WithReconnectMax(DefaultReconnectMax))
	rb.randInt63n = func(n int64) int64 { return 0 }

	_ = rb.DelayAfterFailure() // 1s
	_ = rb.DelayAfterFailure() // 2s
	got := rb.DelayAfterFailure()
	want := 4 * time.Second
	if got != want {
		t.Fatalf("after 3 failures delay = %s; want %s", got, want)
	}
}

func TestReconnectBackoff_CapsAtMax(t *testing.T) {
	rb := NewReconnectBackoff(DefaultReconnectBase, WithReconnectMax(DefaultReconnectMax))
	rb.randInt63n = func(n int64) int64 { return 0 }

	var got time.Duration
	for range 20 {
		got = rb.DelayAfterFailure()
	}
	if got != DefaultReconnectMax {
		t.Fatalf("after many failures delay = %s; want cap %s", got, DefaultReconnectMax)
	}
}

func TestReconnectBackoff_ResetsOnSuccess(t *testing.T) {
	rb := NewReconnectBackoff(DefaultReconnectBase, WithReconnectMax(DefaultReconnectMax))
	rb.randInt63n = func(n int64) int64 { return 0 }

	_ = rb.DelayAfterFailure()
	_ = rb.DelayAfterFailure()
	rb.Reset()
	got := rb.DelayAfterFailure()
	if got != DefaultReconnectBase {
		t.Fatalf("after reset delay = %s; want base %s", got, DefaultReconnectBase)
	}
}
