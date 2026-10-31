// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"encoding/binary"
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
	// muxCredit (signaling protocol 4) is a reader's grant: the path's kind
	// byte, then the bytes it read since its last grant (uvarint).
	muxCredit byte = 'c'
)

// RelayMux splits one p2p.v1 relay stream, after the offer/answer, into a
// signaling path (sequenced Frames for a SignalConn) and a data byte stream
// (the file transfer's relay fallback). Every stream message starts with its
// kind byte.
//
// Each path is flow-controlled on its own (signaling protocol 4): a sender
// sends only what the peer's reader has room for (the path's window) and
// waits for the reader's credit grants for more, so a slow reader slows only
// its own path's sender, the demux never waits, and the other path flows.
// Both ends must speak protocol 4: a peer below it never grants credit.
type RelayMux struct {
	sendMu    sync.Mutex
	send      func([]byte) error
	closeSend func() error // client side only: half-closes the stream
	closeOnce sync.Once

	// Receive side: each path's queue, at most its window.
	sig  muxQueue[*Frame]
	data muxQueue[[]byte]
	// Send side: each path's credit, what the peer's queue has room for.
	sigWin, dataWin sendWindow

	quit chan struct{} // closed by Close: stop delivering
	qOne sync.Once
}

// Per-path windows: bytes sent and not yet read (and granted back).
const (
	muxSignalMax = 1 << 20  // signaling frames
	muxDataMax   = 16 << 20 // file data (secure records of up to 64 KiB)
)

// ErrMuxOverrun is a read on a relay mux path whose peer sent past the
// path's window (a protocol violation: it ignored its credit). The path is
// failed after what arrived within the window; the other path is unaffected.
var ErrMuxOverrun = errors.New("p2p: relay stream path overrun: the peer sent past its credit")

// sendWindow is one path's send credit.
type sendWindow struct {
	mu      sync.Mutex
	avail   int
	err     error
	changed chan struct{} // closed and replaced on every change
}

func newSendWindow(n int) sendWindow {
	return sendWindow{avail: n, changed: make(chan struct{})}
}

func (w *sendWindow) update(f func()) {
	w.mu.Lock()
	f()
	close(w.changed)
	w.changed = make(chan struct{})
	w.mu.Unlock()
}

func (w *sendWindow) grant(n int) { w.update(func() { w.avail += n }) }

func (w *sendWindow) fail(err error) {
	w.update(func() {
		if w.err == nil {
			w.err = err
		}
	})
}

// take waits for credit and takes n bytes of it, or (whole false) as many
// as are available, at least one.
func (w *sendWindow) take(n int, whole bool, quit <-chan struct{}) (int, error) {
	for {
		w.mu.Lock()
		if w.err != nil {
			err := w.err
			w.mu.Unlock()
			return 0, err
		}
		if w.avail >= n || (!whole && w.avail > 0) {
			k := min(n, w.avail)
			w.avail -= k
			w.mu.Unlock()
			return k, nil
		}
		changed := w.changed
		w.mu.Unlock()
		select {
		case <-changed:
		case <-quit:
			return 0, errMuxClosed
		}
	}
}

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
	// read is what the reader took since the last credit grant.
	read int
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

// push queues v, or fails the path when v would pass its window (the peer
// ignored its credit); never blocks.
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
// is closed; and the credit to grant the peer now (0: not yet: grants go out
// a quarter window at a time).
func (q *muxQueue[T]) pop(quit <-chan struct{}, closed error) (T, int, error) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			v := q.items[0]
			var zero T
			q.items[0] = zero
			q.items = q.items[1:]
			q.bytes -= q.sizes[0]
			q.read += q.sizes[0]
			q.sizes = q.sizes[1:]
			if len(q.items) > 0 || q.err != nil {
				q.wake() // for another waiting reader
			}
			grant := 0
			if q.read >= q.max/4 {
				grant, q.read = q.read, 0
			}
			q.mu.Unlock()
			return v, grant, nil
		}
		err := q.err
		q.mu.Unlock()
		if err != nil {
			var zero T
			return zero, 0, err
		}
		select {
		case <-q.ready:
		case <-quit:
			var zero T
			return zero, 0, closed
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
		sigWin:    newSendWindow(muxSignalMax),
		dataWin:   newSendWindow(muxDataMax),
		quit:      make(chan struct{}),
	}
}

// demux reads the stream until it ends (or the mux is closed), routing each
// message to its path's queue, or its credit to the path's sender, without
// ever waiting for a reader. Once the stream ends, a sender waiting for
// credit gets errMuxClosed.
func (m *RelayMux) demux(recv func() ([]byte, error)) {
	defer m.sig.end()
	defer m.data.end()
	defer m.sigWin.fail(errMuxClosed)
	defer m.dataWin.fail(errMuxClosed)
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
		case muxCredit:
			n, k := binary.Uvarint(msg[min(2, len(msg)):])
			if len(msg) < 3 || k <= 0 || n > muxDataMax {
				return // malformed: end rather than misread
			}
			switch msg[1] {
			case muxSignal:
				m.sigWin.grant(int(n))
			case muxData:
				m.dataWin.grant(int(n))
			default:
				return
			}
		default:
			return
		}
	}
}

// grant tells the peer its reader read n more bytes of path kind. A failed
// send is the stream's end, which the reader learns from the stream.
func (m *RelayMux) grant(kind byte, n int) {
	if n > 0 {
		_ = m.write(muxCredit, binary.AppendUvarint([]byte{kind}, uint64(n)))
	}
}

// writeData sends b on the data path as the peer's credit allows, waiting
// for more as its reader reads.
func (m *RelayMux) writeData(b []byte) error {
	for len(b) > 0 {
		k, err := m.dataWin.take(len(b), false, m.quit)
		if err != nil {
			return err
		}
		if err := m.write(muxData, b[:k]); err != nil {
			return err
		}
		b = b[k:]
	}
	return nil
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
	if 1+len(b) > muxSignalMax {
		return fmt.Errorf("p2p: signaling frame of %d bytes exceeds the relay window %d", 1+len(b), muxSignalMax)
	}
	if _, err := p.m.sigWin.take(1+len(b), true, p.m.quit); err != nil {
		return err
	}
	return p.m.write(muxSignal, b)
}

func (p muxSignalPath) ReadFrame() (*Frame, error) {
	f, grant, err := p.m.sig.pop(p.m.quit, io.EOF)
	p.m.grant(muxSignal, grant)
	return f, err
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
		send:      m.writeData,
		closeSend: m.Close,
		recv: func() ([]byte, error) {
			b, grant, err := m.data.pop(m.quit, errMuxClosed)
			m.grant(muxData, grant)
			return b, err
		},
	}
}
