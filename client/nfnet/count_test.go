// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"net"
	"testing"
	"time"
)

// endingSession's Read and Write block until the session ends (Reset),
// then return their bytes a moment later: an in-flight call that had
// moved them before the end.
type endingSession struct {
	net.Conn
	inFlight chan struct{}
	ended    chan struct{}
}

func (s *endingSession) block(p []byte) (int, error) {
	s.inFlight <- struct{}{}
	<-s.ended
	time.Sleep(20 * time.Millisecond)
	return len(p), nil
}

func (s *endingSession) Read(p []byte) (int, error)  { return s.block(p) }
func (s *endingSession) Write(p []byte) (int, error) { return s.block(p) }
func (s *endingSession) CloseWrite() error           { return nil }
func (s *endingSession) Close() error                { return s.Reset() }
func (s *endingSession) Reset() error                { close(s.ended); return nil }

// TestCloseEventCountsInFlightCalls (lane UDPLOSS, as nfltr's Pump in lane
// NF1PROXYRACE): a Write and a Read that return after the session's end
// are counted in its close event. The counters were added after the call
// returned, and the event, emitted at the end, read them first: bytes
// that had arrived went uncounted.
func TestCloseEventCountsInFlightCalls(t *testing.T) {
	for _, reset := range []bool{false, true} {
		s := &endingSession{inFlight: make(chan struct{}, 2), ended: make(chan struct{})}
		got := make(chan Event, 1)
		c := &Conn{s: s, events: func(e Event) {
			if e.Kind == "close" {
				got <- e
			}
		}}
		go func() { _, _ = c.Write(make([]byte, 16)) }()
		go func() { _, _ = c.Read(make([]byte, 8)) }()
		<-s.inFlight
		<-s.inFlight
		if reset {
			_ = c.Reset()
		} else {
			_ = c.Close()
		}
		if e := <-got; e.BytesOut != 16 || e.BytesIn != 8 {
			t.Fatalf("reset %v: close event out %d in %d, want 16 and 8 (the calls in flight at the end)", reset, e.BytesOut, e.BytesIn)
		}
	}
}
