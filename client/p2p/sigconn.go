// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// FramePath is one transport for signaling frames: the relay stream
// (RelayMux.SignalPath) or the direct TCP channel (TCPPath).
type FramePath interface {
	WriteFrame(*Frame) error
	ReadFrame() (*Frame, error)
	Close() error
}

// maxAhead bounds the frames a SignalConn holds while it waits for an earlier
// sequence number; more means that frame is lost on every path.
const maxAhead = 4096

// SignalConn carries the signaling frames between the two CLIs (a call's SDP,
// ICE candidates, chat fallback and hangup; a file transfer's WebRTC
// negotiation) over one or more paths at once: the relay stream from the first
// frame, and the direct TCP channel once it connects (AddPath).
//
// Every frame gets the next sequence number and is written on every open
// path; a path that joins first carries the frames sent before it (the last
// maxAhead of them), so a frame still in flight on a path that breaks is
// carried by the newer one (spec/SignalConn.tla NoSilentLoss). The receiver delivers each sequence number once, in order: a copy of
// a number already delivered is dropped (dedupe by sequence number, never by
// payload: two identical frames are two frames), and a frame that overtook an
// earlier one (the direct path is faster than the relay) waits for it. So a
// path joining or failing mid-call loses and duplicates nothing. A path that
// fails is dropped; reads end (io.EOF) when the last path has ended.
type SignalConn struct {
	mu      sync.Mutex // serializes writes: each path sees frames in seq order
	paths   []pathEntry
	added   int // paths added: the next one's id
	sendSeq uint64
	sent    []*Frame // the last maxAhead frames written, for a joining path
	closed  bool

	rmu     sync.Mutex
	next    uint64 // next sequence number to deliver
	ahead   map[uint64]*Frame
	readers int
	ended   bool // the last path ended: in is closed

	in   chan *Frame
	done chan struct{} // closed by Close
	once sync.Once

	e2e *E2E // E2E.SignalConn: every path is sealed; nil for plain frames
}

// NewSignalConn starts a SignalConn of plain frames on its first path (a
// call's local test harness; sessions between two CLIs use E2E.SignalConn).
func NewSignalConn(first FramePath) *SignalConn {
	sc := &SignalConn{
		next:  1,
		ahead: map[uint64]*Frame{},
		in:    make(chan *Frame, 64),
		done:  make(chan struct{}),
	}
	sc.AddPath(first)
	return sc
}

// AddPath adds a path: the frames sent so far and later frames are written on
// it too, and frames read from it are delivered (deduped and in order with
// the other paths).
func (sc *SignalConn) AddPath(p FramePath) {
	if sc.e2e != nil {
		p = sc.e2e.sealPath(p)
	}
	sc.rmu.Lock()
	if sc.ended {
		sc.rmu.Unlock()
		_ = p.Close()
		return
	}
	sc.readers++
	sc.rmu.Unlock()
	sc.mu.Lock()
	e := pathEntry{p, sc.added}
	sc.added++
	if traceOn {
		traceJoin(sc, e.id)
	}
	go sc.readPath(e) // first: the peer's replay may wait for this reader
	ok := !sc.closed
	for _, f := range sc.sent {
		if ok && p.WriteFrame(f) != nil {
			ok = false
		}
	}
	if ok {
		sc.paths = append(sc.paths, e)
	}
	sc.mu.Unlock()
	if !ok {
		_ = p.Close() // its reader ends at once
	}
}

// Paths is the number of open paths.
func (sc *SignalConn) Paths() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return len(sc.paths)
}

// pathEntry is an open path and its id: the order it was added in (the
// relay stream 0; spec/SignalConn.tla's paths, its trace's ids).
type pathEntry struct {
	FramePath
	id int
}

func (sc *SignalConn) readPath(p pathEntry) {
	for {
		f, err := p.ReadFrame()
		if err == nil && traceOn {
			traceRecv(sc, p.id, f.Seq)
		}
		if err != nil || !sc.accept(f) {
			break
		}
	}
	if traceOn {
		traceDrop(sc, p.id)
	}
	sc.dropPath(p.FramePath)
	sc.rmu.Lock()
	sc.readers--
	if sc.readers == 0 {
		sc.ended = true
		close(sc.in)
	}
	sc.rmu.Unlock()
}

// accept delivers f if it is the next sequence number (then any frames
// waiting behind it), keeps it if it is early, and drops a copy already
// delivered. It returns false once the SignalConn is closed or broken.
func (sc *SignalConn) accept(f *Frame) bool {
	sc.rmu.Lock()
	defer sc.rmu.Unlock()
	if f.Seq < sc.next || sc.ahead[f.Seq] != nil {
		return true // a copy from the other path, or seq 0 (unsequenced)
	}
	if f.Seq > sc.next {
		if len(sc.ahead) >= maxAhead {
			_ = sc.Close()
			return false
		}
		sc.ahead[f.Seq] = f
		return true
	}
	for f != nil {
		select {
		case sc.in <- f:
		case <-sc.done:
			return false
		}
		delete(sc.ahead, sc.next)
		sc.next++
		f = sc.ahead[sc.next]
	}
	return true
}

func (sc *SignalConn) dropPath(p FramePath) {
	sc.mu.Lock()
	for i, q := range sc.paths {
		if q.FramePath == p {
			sc.paths = append(sc.paths[:i:i], sc.paths[i+1:]...)
			break
		}
	}
	sc.mu.Unlock()
	_ = p.Close()
}

// maxFrameJSON bounds a frame's JSON so every path takes it: the relay
// window less the sealed envelope (base64 of the frame and its AEAD tag, the
// outer frame's fields) and its sequence number. A larger frame failed only
// on the relay path, which closed it and the data fallback with it.
const maxFrameJSON = (muxSignalMax-256)/4*3 - 16 - 32

// errFrameTooLarge is a frame over maxFrameJSON.
var errFrameTooLarge = errors.New("p2p: signaling frame too large for the relay window")

// WriteFrame numbers f and writes it on every open path. It fails only when
// no path took it; such a frame is not numbered or replayed to a later path.
func (sc *SignalConn) WriteFrame(f *Frame) error {
	if b, err := json.Marshal(f); err != nil {
		return fmt.Errorf("p2p: marshal frame: %w", err)
	} else if len(b) > maxFrameJSON {
		return errFrameTooLarge
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed {
		return io.ErrClosedPipe
	}
	sc.sendSeq++
	g := *f
	g.Seq = sc.sendSeq
	if traceOn {
		traceWrite(sc, g.Seq, sc.paths)
	}
	var err error
	sent := 0
	for _, p := range sc.paths {
		if werr := p.WriteFrame(&g); werr != nil {
			err = werr
			_ = p.Close() // its reader ends and drops it
			continue
		}
		sent++
	}
	if sent > 0 {
		// ponytail: a path joining after more than maxAhead frames misses
		// the older ones; one of them lost on every other path fills the
		// reader's ahead and closes it (accept), never a silent stall.
		if len(sc.sent) == maxAhead {
			sc.sent = sc.sent[1:]
		}
		sc.sent = append(sc.sent, &g)
		return nil
	}
	sc.sendSeq-- // no path took it: the caller sees the error, no peer the frame
	if err == nil {
		err = io.ErrClosedPipe
	}
	return err
}

// ReadFrame returns the next frame in sequence order; io.EOF once every path
// has ended or the SignalConn is closed.
func (sc *SignalConn) ReadFrame() (*Frame, error) {
	select {
	case f, ok := <-sc.in:
		if !ok {
			return nil, io.EOF
		}
		return f, nil
	case <-sc.done:
		return nil, io.EOF
	}
}

// Close closes every path.
func (sc *SignalConn) Close() error {
	sc.once.Do(func() { close(sc.done) })
	sc.mu.Lock()
	sc.closed = true
	paths := sc.paths
	sc.mu.Unlock()
	for _, p := range paths {
		_ = p.Close()
	}
	return nil
}

// tcpWriteTimeout bounds one frame write on the direct channel, so a path that
// stopped draining is dropped instead of stalling the others.
const tcpWriteTimeout = 10 * time.Second

type tcpPath struct{ conn net.Conn }

// TCPPath is a FramePath over a byte stream (the direct TCP channel): frames
// are length-prefixed JSON (writeFrame/readFrame).
func TCPPath(conn net.Conn) FramePath { return tcpPath{conn} }

func (t tcpPath) WriteFrame(f *Frame) error {
	_ = t.conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
	return writeFrame(t.conn, f)
}

// ReadFrame reads one length-prefixed frame (FramePath). allow:wrapper
func (t tcpPath) ReadFrame() (*Frame, error) { return readFrame(t.conn) }

// Close closes the TCP connection (FramePath). allow:wrapper
func (t tcpPath) Close() error { return t.conn.Close() }

// AddDirectPath tries the direct TCP channel (Connect) while signaling already
// flows over sc's relay path; on success the channel becomes another path.
// The returned channel yields the connection (nil if none) once the attempt
// ends.
func AddDirectPath(ctx context.Context, sc *SignalConn, ln *net.TCPListener, theirCandidates []string,
	token []byte, sessionID, role string,
) <-chan net.Conn {
	out := make(chan net.Conn, 1)
	go func() {
		conn, err := Connect(ctx, ln, theirCandidates, token, sessionID, role)
		if err != nil {
			out <- nil
			return
		}
		sc.AddPath(TCPPath(conn))
		out <- conn
	}()
	return out
}
