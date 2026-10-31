// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
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

// A peer that sends data past its credit (a protocol violation) fails the
// data channel with ErrMuxOverrun (after what was queued); signaling keeps
// flowing.
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

// memPipe is one direction of an in-memory relay stream that never pushes
// back (the worst case for a sender's memory: the relay buffers whatever it
// is given). It counts the data bytes the sender put in.
type memPipe struct {
	mu     sync.Mutex
	msgs   [][]byte
	closed bool
	ready  chan struct{}
	data   atomic.Int64 // data payload bytes sent
}

func newMemPipe() *memPipe { return &memPipe{ready: make(chan struct{}, 1)} }

func (p *memPipe) send(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return io.ErrClosedPipe
	}
	if len(b) > 0 && b[0] == muxData {
		p.data.Add(int64(len(b) - 1))
	}
	p.msgs = append(p.msgs, append([]byte(nil), b...))
	select {
	case p.ready <- struct{}{}:
	default:
	}
	return nil
}

func (p *memPipe) closeSend() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	select {
	case p.ready <- struct{}{}:
	default:
	}
	return nil
}

func (p *memPipe) recv() ([]byte, error) {
	for {
		p.mu.Lock()
		if len(p.msgs) > 0 {
			b := p.msgs[0]
			p.msgs = p.msgs[1:]
			if len(p.msgs) > 0 {
				select {
				case p.ready <- struct{}{}:
				default:
				}
			}
			p.mu.Unlock()
			return b, nil
		}
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return nil, io.EOF
		}
		<-p.ready
	}
}

// A transfer far larger than the data window to a reader that is slow (and
// stops for a while at the start) completes byte-exact over the relay mux;
// signaling keeps flowing both ways throughout; the bytes the sender has put
// on the stream and the reader has not read never pass the data window.
func TestRelayMuxSlowReaderLargeTransfer(t *testing.T) {
	const total = 64 << 20
	ab, ba := newMemPipe(), newMemPipe()
	snd := newRelayMux(ab.send, ab.closeSend)
	rcv := newRelayMux(ba.send, nil)
	go snd.demux(ba.recv)
	go rcv.demux(ab.recv)
	t.Cleanup(func() { _ = snd.SignalPath().Close(); _ = rcv.SignalPath().Close(); _ = ba.closeSend() })

	src := make([]byte, total)
	_, _ = crand.Read(src)
	var read, peak atomic.Int64
	start := time.Now()

	stop, pinged := make(chan struct{}), make(chan struct{})
	sendErr := make(chan error, 1)
	go func() {
		conn := snd.DataConn()
		for off := 0; off < total; off += 1 << 20 {
			if _, err := conn.Write(src[off : off+1<<20]); err != nil {
				sendErr <- err
				return
			}
		}
		<-pinged // closing the data conn half-closes the stream: signaling too
		sendErr <- conn.Close()
	}()

	// Signaling ping-pong during the transfer: each round trip in time.
	pingDone := make(chan error, 1)
	go func() {
		for {
			f, err := rcv.SignalPath().ReadFrame()
			if err != nil {
				return
			}
			_ = rcv.SignalPath().WriteFrame(&Frame{Type: FrameAck, Name: "pong-" + f.Name})
		}
	}()
	go func() {
		defer close(pinged)
		n := 0
		for {
			select {
			case <-stop:
				if n < 5 {
					pingDone <- fmt.Errorf("only %d signaling round trips", n)
					return
				}
				pingDone <- nil
				return
			case <-time.After(20 * time.Millisecond):
			}
			name := strconv.Itoa(n)
			if err := snd.SignalPath().WriteFrame(&Frame{Type: FrameChat, Name: name}); err != nil {
				pingDone <- err
				return
			}
			pong := make(chan *Frame, 1)
			go func() { f, _ := snd.SignalPath().ReadFrame(); pong <- f }()
			select {
			case f := <-pong:
				if f == nil || f.Name != "pong-"+name {
					pingDone <- fmt.Errorf("pong %d = %+v", n, f)
					return
				}
			case <-time.After(2 * time.Second):
				pingDone <- fmt.Errorf("signaling round trip %d stalled", n)
				return
			}
			n++
		}
	}()

	got := make([]byte, 0, total)
	conn := rcv.DataConn()
	buf := make([]byte, 32<<10)
	time.Sleep(300 * time.Millisecond) // the reader stops for a while first
	for len(got) < total {
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		read.Add(int64(n))
		if ahead := ab.data.Load() - read.Load(); ahead > peak.Load() {
			peak.Store(ahead)
		}
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(got), err)
		}
		if len(got)%(1<<20) < len(buf) {
			time.Sleep(5 * time.Millisecond) // a slow reader
		}
	}
	elapsed := time.Since(start)
	close(stop)
	if err := <-pingDone; err != nil {
		t.Fatal(err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("send: %v", err)
	}
	if n, err := conn.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("read after the transfer = %d, %v; want EOF", n, err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("received %d bytes, not the %d sent", len(got), total)
	}
	if p := peak.Load(); p > muxDataMax {
		t.Fatalf("sender was up to %d bytes ahead of the reader, window %d", p, muxDataMax)
	}
	t.Logf("%d MiB in %v (%.0f MiB/s), sender at most %d KiB ahead of the reader",
		total>>20, elapsed.Round(time.Millisecond), float64(total>>20)/elapsed.Seconds(), peak.Load()>>10)
}
