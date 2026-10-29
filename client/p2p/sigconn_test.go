// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// chanPath is a FramePath the test feeds by hand.
type chanPath struct {
	in      chan *Frame
	written chan *Frame
	closed  chan struct{}
}

func newChanPath() *chanPath {
	return &chanPath{in: make(chan *Frame, 16), written: make(chan *Frame, 1024), closed: make(chan struct{})}
}

func (p *chanPath) WriteFrame(f *Frame) error {
	select {
	case <-p.closed:
		return io.ErrClosedPipe
	default:
	}
	g := *f
	p.written <- &g
	return nil
}

func (p *chanPath) ReadFrame() (*Frame, error) {
	select {
	case f, ok := <-p.in:
		if !ok {
			return nil, io.EOF
		}
		return f, nil
	case <-p.closed:
		return nil, io.EOF
	}
}

func (p *chanPath) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	return nil
}

func readN(t *testing.T, sc *SignalConn, n int) []*Frame {
	t.Helper()
	var out []*Frame
	for range n {
		got := make(chan *Frame, 1)
		go func() {
			f, err := sc.ReadFrame()
			if err != nil {
				f = nil
			}
			got <- f
		}()
		select {
		case f := <-got:
			if f == nil {
				t.Fatalf("read %d of %d: connection ended", len(out), n)
			}
			out = append(out, f)
		case <-time.After(5 * time.Second):
			t.Fatalf("read %d of %d: timed out", len(out), n)
		}
	}
	return out
}

// A frame that arrives on both paths is delivered once; a frame that
// overtakes an earlier one waits for it.
func TestSignalConnDedupesAndOrdersBySeq(t *testing.T) {
	relay, direct := newChanPath(), newChanPath()
	sc := NewSignalConn(relay)
	defer sc.Close() //nolint:errcheck
	sc.AddPath(direct)

	direct.in <- &Frame{Type: FrameChat, Text: "b", Seq: 2} // overtakes 1
	relay.in <- &Frame{Type: FrameChat, Text: "a", Seq: 1}
	relay.in <- &Frame{Type: FrameChat, Text: "b", Seq: 2} // the relay's copy
	direct.in <- &Frame{Type: FrameChat, Text: "a", Seq: 1}
	relay.in <- &Frame{Type: FrameChat, Text: "c", Seq: 3}
	direct.in <- &Frame{Type: FrameChat, Text: "c", Seq: 3}
	relay.in <- &Frame{Type: FrameChat, Text: "zero", Seq: 0} // unsequenced: never delivered

	got := readN(t, sc, 3)
	for i, want := range []string{"a", "b", "c"} {
		if got[i].Text != want || got[i].Seq != uint64(i+1) {
			t.Fatalf("frame %d = %+v, want %q seq %d", i, got[i], want, i+1)
		}
	}
	close(relay.in)
	close(direct.in)
	if f, err := sc.ReadFrame(); err != io.EOF {
		t.Fatalf("after both paths ended: %+v, %v; want io.EOF (no duplicate, no seq 0)", f, err)
	}
}

// Identical payloads are distinct frames: dedupe is by sequence number, never
// by content (the relay's payload-equality dedupe dropped real data).
func TestSignalConnDeliversIdenticalPayloads(t *testing.T) {
	relay := newChanPath()
	sc := NewSignalConn(relay)
	defer sc.Close() //nolint:errcheck
	for i := range 3 {
		relay.in <- &Frame{Type: FrameRTC, Text: `{"type":"ice-candidate"}`, Seq: uint64(i + 1)}
	}
	if got := readN(t, sc, 3); got[2].Seq != 3 {
		t.Fatalf("got %+v", got)
	}
}

// WriteFrame numbers frames and writes each on every open path; a path that
// fails is dropped and the others keep the frame.
func TestSignalConnWritesEveryPath(t *testing.T) {
	relay, direct := newChanPath(), newChanPath()
	sc := NewSignalConn(relay)
	defer sc.Close() //nolint:errcheck
	if err := sc.WriteFrame(&Frame{Type: FrameChat, Text: "1"}); err != nil {
		t.Fatal(err)
	}
	sc.AddPath(direct)
	if err := sc.WriteFrame(&Frame{Type: FrameChat, Text: "2"}); err != nil {
		t.Fatal(err)
	}
	_ = direct.Close()
	if err := sc.WriteFrame(&Frame{Type: FrameChat, Text: "3"}); err != nil {
		t.Fatalf("a failed path must not fail the write: %v", err)
	}
	for _, want := range []uint64{1, 2, 3} {
		if f := <-relay.written; f.Seq != want {
			t.Fatalf("relay got seq %d, want %d", f.Seq, want)
		}
	}
	if f := <-direct.written; f.Seq != 2 || len(direct.written) != 0 {
		t.Fatalf("direct got seq %d (+%d more), want only 2", f.Seq, len(direct.written))
	}
	_ = relay.Close()
	waitPaths(t, sc, 0)
	if err := sc.WriteFrame(&Frame{Type: FrameChat}); err == nil {
		t.Fatal("write with no path left must fail")
	}
}

func waitPaths(t *testing.T, sc *SignalConn, n int) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); sc.Paths() != n; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("paths = %d, want %d", sc.Paths(), n)
		}
	}
}

// pipePath is one side of a FramePath pair over net.Pipe.
func pipePaths() (FramePath, FramePath) {
	a, b := net.Pipe()
	return TCPPath(a), TCPPath(b)
}

// The switch: a call whose direct path joins mid-stream and whose relay path
// later dies delivers every frame exactly once, in order, both ways.
func TestSignalConnSwitchLosesNothing(t *testing.T) {
	relayA, relayB := pipePaths()
	alice, bob := NewSignalConn(relayA), NewSignalConn(relayB)
	defer alice.Close() //nolint:errcheck
	defer bob.Close()   //nolint:errcheck

	const n = 200
	errs := make(chan error, 2)
	send := func(sc *SignalConn, who string) {
		for i := 1; i <= n; i++ {
			if err := sc.WriteFrame(&Frame{Type: FrameChat, Text: fmt.Sprintf("%s-%d", who, i)}); err != nil {
				errs <- err
				return
			}
			if i == n/2 {
				time.Sleep(20 * time.Millisecond) // the other side adds its path too
			}
		}
		errs <- nil
	}
	recv := func(sc *SignalConn) []*Frame { return readN(t, sc, n) }

	directA, directB := pipePaths()
	go send(alice, "a")
	go send(bob, "b")
	gotBob := make(chan []*Frame, 1)
	go func() { gotBob <- recv(bob) }()
	var gotAlice []*Frame
	done := make(chan struct{})
	go func() { gotAlice = recv(alice); close(done) }()
	time.Sleep(5 * time.Millisecond)
	alice.AddPath(directA)
	bob.AddPath(directB)
	time.Sleep(10 * time.Millisecond)
	_ = relayA.Close() // the relay goes away mid-call

	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	<-done
	for who, got := range map[string][]*Frame{"a": <-gotBob, "b": gotAlice} {
		for i, f := range got {
			if want := fmt.Sprintf("%s-%d", who, i+1); f.Text != want || f.Seq != uint64(i+1) {
				t.Fatalf("frame %d from %s = %q seq %d, want %q", i, who, f.Text, f.Seq, want)
			}
		}
	}
}

// A frame lost on every path ends the connection instead of buffering
// forever.
func TestSignalConnGapIsBounded(t *testing.T) {
	relay := newChanPath()
	relay.in = make(chan *Frame, maxAhead+2)
	sc := NewSignalConn(relay)
	for i := range maxAhead + 1 {
		relay.in <- &Frame{Type: FrameChat, Seq: uint64(i + 2)} // seq 1 never comes
	}
	got := make(chan error, 1)
	go func() { _, err := sc.ReadFrame(); got <- err }()
	select {
	case err := <-got:
		if err != io.EOF {
			t.Fatalf("got %v, want io.EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a gap past maxAhead did not end the connection")
	}
}
