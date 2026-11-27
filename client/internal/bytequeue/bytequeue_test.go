// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package bytequeue

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestQueueBoundsBytesAndDrainsAfterClose(t *testing.T) {
	q := New(4)
	if !q.Push([]byte("ab")) || !q.Push([]byte("cd")) {
		t.Fatal("pushes under the limit must not block or fail")
	}

	pushed := make(chan bool, 1)
	go func() { pushed <- q.Push([]byte("ef")) }()
	select {
	case <-pushed:
		t.Fatal("push into a full queue must wait")
	case <-time.After(50 * time.Millisecond):
	}

	if b, ok := q.Pop(); !ok || string(b) != "ab" {
		t.Fatalf("Pop = %q, %v", b, ok)
	}
	if !<-pushed {
		t.Fatal("push must proceed once bytes are popped")
	}

	q.Close()
	if q.Push([]byte("x")) {
		t.Fatal("push after Close must fail")
	}
	for _, want := range []string{"cd", "ef"} {
		if b, ok := q.Pop(); !ok || string(b) != want {
			t.Fatalf("Pop after Close = %q, %v; want %q", b, ok, want)
		}
	}
	if _, ok := q.Pop(); ok {
		t.Fatal("Pop on a closed, drained queue must report false")
	}
}

func TestPopBatchTakesBacklogUpToMax(t *testing.T) {
	q := New(100)
	for _, s := range []string{"ab", "cd", "ef", "gh"} {
		q.Push([]byte(s))
	}
	got, ok := q.PopBatch([][]byte{[]byte("x")}, 5)
	if !ok || len(got) != 3 || string(got[1]) != "ab" || string(got[2]) != "cd" {
		t.Fatalf("PopBatch = %q, %v; want x, ab, cd (4 bytes <= 5)", got, ok)
	}
	if got, ok = q.PopBatch(nil, 1); !ok || len(got) != 1 || string(got[0]) != "ef" {
		t.Fatalf("PopBatch over max = %q, %v; want one slice", got, ok)
	}
	q.Close()
	if got, ok = q.PopBatch(nil, 10); !ok || len(got) != 1 || string(got[0]) != "gh" {
		t.Fatalf("PopBatch after Close = %q, %v", got, ok)
	}
	if _, ok = q.PopBatch(nil, 10); ok {
		t.Fatal("PopBatch on a closed, drained queue must report false")
	}
}

func TestCloseWakesBlockedPushAndPop(t *testing.T) {
	full := New(1)
	full.Push([]byte("a"))
	empty := New(1)

	done := make(chan bool, 2)
	go func() { done <- full.Push([]byte("b")) }()
	go func() { _, ok := empty.Pop(); done <- ok }()
	time.Sleep(20 * time.Millisecond)
	full.Close()
	empty.Close()
	for range 2 {
		select {
		case ok := <-done:
			if ok {
				t.Fatal("waiter woken by Close must report false")
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not wake a waiter")
		}
	}
}

// TestOnPopReportsBytesTaken guards the hook a data connection returns
// credit with: every pop reports the bytes it took, closed-queue drains
// included, and an empty pop reports nothing.
func TestOnPopReportsBytesTaken(t *testing.T) {
	q := New(1 << 10)
	var got []int
	q.OnPop(func(n int) { got = append(got, n) })
	q.Push([]byte("abc"))
	q.Push([]byte("de"))
	q.Push([]byte("f"))
	if _, ok := q.PopBatch(nil, 5); !ok {
		t.Fatal("PopBatch failed")
	}
	q.Close()
	if _, ok := q.Pop(); !ok {
		t.Fatal("Pop of the queued tail failed")
	}
	if _, ok := q.Pop(); ok {
		t.Fatal("Pop of a drained closed queue succeeded")
	}
	if len(got) != 2 || got[0] != 5 || got[1] != 1 {
		t.Fatalf("OnPop reported %v, want [5 1]", got)
	}
}

// A queue that drains reuses its array: pushes and pops in turn allocate
// nothing.
func TestDrainedQueueReusesItsArray(t *testing.T) {
	q := New(1 << 20)
	b := []byte("x")
	var dst [][]byte
	q.Push(b)
	q.Push(b)
	dst, _ = q.PopBatch(dst[:0], 10)
	if n := testing.AllocsPerRun(100, func() {
		q.Push(b)
		q.Push(b)
		dst, _ = q.PopBatch(dst[:0], 10)
		q.Push(b)
		q.Pop()
	}); n != 0 {
		t.Fatalf("%.1f allocations per push/pop round", n)
	}
}

// TestNewRefusesNoLimit: a queue that would take nothing panics at New,
// saying why, instead of blocking its first Push for good.
func TestNewRefusesNoLimit(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "limit") {
			t.Fatalf("New(0) recovered %v, want a panic about the limit", r)
		}
	}()
	New(0)
}
