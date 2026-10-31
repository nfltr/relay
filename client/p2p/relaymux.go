// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/nfltr/relay/client/rpcclient"
)

// Relay stream message kinds after the offer/answer (signaling protocol 2):
// the first byte of every stream message.
const (
	muxSignal byte = 's' // one JSON Frame (a SignalConn path)
	muxData   byte = 'd' // file bytes on the relay fallback (RelayMux.DataConn)
)

// RelayMux splits one p2p.v1 relay stream, after the offer/answer, into a
// signaling path (sequenced Frames for a SignalConn) and a data byte stream
// (the file transfer's relay fallback). Every stream message starts with its
// kind byte.
type RelayMux struct {
	sendMu    sync.Mutex
	send      func([]byte) error
	closeSend func() error // client side only: half-closes the stream
	closeOnce sync.Once

	// Each path has its own bounded queue, so a reader that stops reading
	// fails only its own path (ErrMuxOverrun) and never stalls the demux,
	// and with it the other path. The stream has no per-path credit: a
	// path past its bound is failed, not paused.
	sig  muxQueue[*Frame]
	data muxQueue[[]byte]
	quit chan struct{} // closed by Close: stop delivering
	qOne sync.Once
}

// Per-path bounds on bytes received and not yet read.
const (
	muxSignalMax = 1 << 20  // signaling frames
	muxDataMax   = 16 << 20 // file data (secure records of up to 64 KiB)
)

// ErrMuxOverrun is a read on a relay mux path whose reader left more than
// the path's bound unread: the path is failed (what arrived before the bound
// is still read first); the other path is unaffected.
var ErrMuxOverrun = errors.New("p2p: relay stream path overrun: its reader stopped reading")

// muxQueue is one path's queue: bounded in bytes, with a sticky end error.
type muxQueue[T any] struct {
	name  string
	max   int
	mu    sync.Mutex
	items []T
	sizes []int
	bytes int
	err   error         // the path's end (io.EOF) or failure, after items
	ready chan struct{} // capacity 1: something changed
}

func newMuxQueue[T any](name string, max int) muxQueue[T] {
	return muxQueue[T]{name: name, max: max, ready: make(chan struct{}, 1)}
}

func (q *muxQueue[T]) wake() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// push queues v, or fails the path when v would pass its bound; never blocks.
func (q *muxQueue[T]) push(v T, size int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return // failed or ended: its reader gets q.err
	}
	if q.bytes+size > q.max {
		q.err = fmt.Errorf("%w (%s path: %d bytes unread, bound %d)", ErrMuxOverrun, q.name, q.bytes, q.max)
	} else {
		q.items = append(q.items, v)
		q.sizes = append(q.sizes, size)
		q.bytes += size
	}
	q.wake()
}

// end marks the stream's end: the reader gets io.EOF after the queued items.
func (q *muxQueue[T]) end() {
	q.mu.Lock()
	if q.err == nil {
		q.err = io.EOF
	}
	q.mu.Unlock()
	q.wake()
}

// pop returns the next item, the path's end or failure, or closed once quit
// is closed.
func (q *muxQueue[T]) pop(quit <-chan struct{}, closed error) (T, error) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			v := q.items[0]
			var zero T
			q.items[0] = zero
			q.items = q.items[1:]
			q.bytes -= q.sizes[0]
			q.sizes = q.sizes[1:]
			if len(q.items) > 0 || q.err != nil {
				q.wake() // for another waiting reader
			}
			q.mu.Unlock()
			return v, nil
		}
		err := q.err
		q.mu.Unlock()
		if err != nil {
			var zero T
			return zero, err
		}
		select {
		case <-q.ready:
		case <-quit:
			var zero T
			return zero, closed
		}
	}
}

// NewClientRelayMux starts a mux on the initiator's stream.
func NewClientRelayMux(stream rpcclient.ClientStream) *RelayMux {
	m := newRelayMux(stream.Send, stream.CloseSend)
	go m.demux(func() ([]byte, error) {
		resp, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		return resp.Data, nil
	})
	return m
}

// NewServerRelayMux starts a mux on the responder's stream.
func NewServerRelayMux(stream rpcclient.ServerStream) *RelayMux {
	m := newRelayMux(stream.Send, nil)
	go m.demux(stream.Recv)
	return m
}

func newRelayMux(send func([]byte) error, closeSend func() error) *RelayMux {
	return &RelayMux{
		send:      send,
		closeSend: closeSend,
		sig:       newMuxQueue[*Frame]("signaling", muxSignalMax),
		data:      newMuxQueue[[]byte]("data", muxDataMax),
		quit:      make(chan struct{}),
	}
}

// demux reads the stream until it ends (or the mux is closed), routing each
// message to its path's queue without ever waiting for a reader.
func (m *RelayMux) demux(recv func() ([]byte, error)) {
	defer m.sig.end()
	defer m.data.end()
	for {
		msg, err := recv()
		if err != nil || len(msg) == 0 {
			return
		}
		select {
		case <-m.quit:
			return
		default:
		}
		switch msg[0] {
		case muxSignal:
			var f Frame
			if json.Unmarshal(msg[1:], &f) != nil {
				return // not protocol 2: end rather than misread
			}
			m.sig.push(&f, len(msg))
		case muxData:
			m.data.push(msg[1:], len(msg)-1)
		default:
			return
		}
	}
}

func (m *RelayMux) write(kind byte, b []byte) error {
	msg := make([]byte, 1+len(b))
	msg[0] = kind
	copy(msg[1:], b)
	m.sendMu.Lock()
	defer m.sendMu.Unlock()
	return m.send(msg)
}

// Close half-closes the stream (initiator) and stops delivering.
func (m *RelayMux) Close() error {
	var err error
	m.closeOnce.Do(func() {
		if m.closeSend != nil {
			err = m.closeSend()
		}
	})
	return err
}

// SignalPath is the mux's signaling FramePath. Closing it closes the mux.
func (m *RelayMux) SignalPath() FramePath { return muxSignalPath{m} }

type muxSignalPath struct{ m *RelayMux }

func (p muxSignalPath) WriteFrame(f *Frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("p2p: marshal frame: %w", err)
	}
	return p.m.write(muxSignal, b)
}

func (p muxSignalPath) ReadFrame() (*Frame, error) {
	return p.m.sig.pop(p.m.quit, io.EOF)
}

func (p muxSignalPath) Close() error {
	p.m.qOne.Do(func() { close(p.m.quit) })
	return p.m.Close()
}

// errMuxClosed is a read on a closed mux.
var errMuxClosed = errors.New("p2p: relay stream closed")

// DataConn is the relay fallback for file data, as a byte stream on the same
// relay stream (RelayConn semantics: an empty message or the stream's end is
// io.EOF; Close half-closes the initiator's stream).
func (m *RelayMux) DataConn() *RelayConn {
	return &RelayConn{
		send:      func(b []byte) error { return m.write(muxData, b) },
		closeSend: m.Close,
		recv:      func() ([]byte, error) { return m.data.pop(m.quit, errMuxClosed) },
	}
}
