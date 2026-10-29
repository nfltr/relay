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

	sig  chan *Frame
	data chan []byte
	quit chan struct{} // closed by Close: stop delivering
	qOne sync.Once
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
		sig:       make(chan *Frame, 64),
		data:      make(chan []byte, 8),
		quit:      make(chan struct{}),
	}
}

// demux reads the stream until it ends, routing each message by kind.
func (m *RelayMux) demux(recv func() ([]byte, error)) {
	defer close(m.sig)
	defer close(m.data)
	for {
		msg, err := recv()
		if err != nil || len(msg) == 0 {
			return
		}
		switch msg[0] {
		case muxSignal:
			var f Frame
			if json.Unmarshal(msg[1:], &f) != nil {
				return // not protocol 2: end rather than misread
			}
			select {
			case m.sig <- &f:
			case <-m.quit:
				return
			}
		case muxData:
			select {
			case m.data <- msg[1:]:
			case <-m.quit:
				return
			}
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
	select {
	case f, ok := <-p.m.sig:
		if !ok {
			return nil, io.EOF
		}
		return f, nil
	case <-p.m.quit:
		return nil, io.EOF
	}
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
		recv: func() ([]byte, error) {
			select {
			case b, ok := <-m.data:
				if !ok {
					return nil, io.EOF
				}
				return b, nil
			case <-m.quit:
				return nil, errMuxClosed
			}
		},
	}
}
