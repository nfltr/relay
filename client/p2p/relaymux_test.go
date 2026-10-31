// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// startTestMux runs a mux whose stream delivers msgs, then blocks until the
// test ends (an open stream).
func startTestMux(t *testing.T, dataMax int, msgs ...[]byte) *RelayMux {
	t.Helper()
	m := newRelayMux(func([]byte) error { return nil }, nil)
	if dataMax > 0 {
		m.data.max = dataMax
	}
	in := make(chan []byte, len(msgs))
	for _, msg := range msgs {
		in <- msg
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); _ = m.SignalPath().Close() })
	go m.demux(func() ([]byte, error) {
		select {
		case b := <-in:
			return b, nil
		case <-done:
			return nil, errors.New("test over")
		}
	})
	return m
}

func sigMsg(t *testing.T, f *Frame) []byte {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{muxSignal}, b...)
}

func readFrameWithin(t *testing.T, p FramePath, d time.Duration) (*Frame, error) {
	t.Helper()
	type res struct {
		f   *Frame
		err error
	}
	ch := make(chan res, 1)
	go func() { f, err := p.ReadFrame(); ch <- res{f, err} }()
	select {
	case r := <-ch:
		return r.f, r.err
	case <-time.After(d):
		t.Fatal("signaling stalled behind an unread data channel")
		return nil, nil
	}
}

// An unread data channel must not stall signaling on the same stream.
func TestRelayMuxUnreadDataDoesNotStallSignaling(t *testing.T) {
	var msgs [][]byte
	for i := 0; i < 32; i++ {
		msgs = append(msgs, append([]byte{muxData}, make([]byte, 1024)...))
	}
	msgs = append(msgs, sigMsg(t, &Frame{Type: FrameAck, Name: "after-data"}))
	m := startTestMux(t, 0, msgs...)

	f, err := readFrameWithin(t, m.SignalPath(), 5*time.Second)
	if err != nil || f.Name != "after-data" {
		t.Fatalf("ReadFrame = %+v, %v", f, err)
	}
	// The data that arrived is all still there, in order.
	conn := m.DataConn()
	buf := make([]byte, 1024)
	for i := 0; i < 32; i++ {
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("data read %d: %v", i, err)
		}
	}
}

// A data reader past the bound fails its own channel with ErrMuxOverrun
// (after what was queued); signaling keeps flowing.
func TestRelayMuxDataOverrunFailsOnlyDataChannel(t *testing.T) {
	m := startTestMux(t, 2048,
		append([]byte{muxData}, make([]byte, 1024)...),
		append([]byte{muxData}, make([]byte, 1024)...),
		append([]byte{muxData}, make([]byte, 1024)...), // over the bound
		sigMsg(t, &Frame{Type: FrameAck, Name: "still-flows"}),
	)
	f, err := readFrameWithin(t, m.SignalPath(), 5*time.Second)
	if err != nil || f.Name != "still-flows" {
		t.Fatalf("ReadFrame = %+v, %v", f, err)
	}
	conn := m.DataConn()
	buf := make([]byte, 1024)
	for i := 0; i < 2; i++ {
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("queued data read %d: %v", i, err)
		}
	}
	if _, err := conn.Read(buf); !errors.Is(err, ErrMuxOverrun) {
		t.Fatalf("read past overrun = %v, want ErrMuxOverrun", err)
	}
}
