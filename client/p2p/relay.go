// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/nfltr/relay/client/rpcclient"
)

const (
	// SignalRelay is sent by the initiator when direct P2P fails, instructing
	// both sides to relay data through the server's A2A channel.
	SignalRelay SignalType = "relay"

	// relayMaxChunk is the maximum chunk size sent over the relay.
	// Keep under gRPC frame limits (~4 MB default).
	relayMaxChunk = 256 * 1024
)

// RelayConn wraps a bidirectional A2A stream as a net.Conn so the existing
// P2P transfer/chat/call code can use it unchanged.  Data is relayed through
// the server instead of flowing peer-to-peer.
type RelayConn struct {
	send      func([]byte) error
	recv      func() ([]byte, error)
	closeSend func() error // the client's half-close: the peer's Read sees EOF

	mu      sync.Mutex
	closed  bool
	readBuf []byte // partial read buffer
}

// NewClientRelayConn wraps a ClientStream as a net.Conn for relay.
func NewClientRelayConn(stream rpcclient.ClientStream) *RelayConn {
	return &RelayConn{
		send:      stream.Send,
		closeSend: stream.CloseSend,
		recv: func() ([]byte, error) {
			resp, err := stream.Recv()
			if err != nil {
				return nil, err
			}
			return resp.Data, nil
		},
	}
}

// NewServerRelayConn wraps a ServerStream as a net.Conn for relay.
func NewServerRelayConn(stream rpcclient.ServerStream) *RelayConn {
	return &RelayConn{
		send: stream.Send,
		recv: stream.Recv,
	}
}

// Read implements net.Conn.
func (rc *RelayConn) Read(b []byte) (int, error) {
	if len(rc.readBuf) > 0 {
		n := copy(b, rc.readBuf)
		rc.readBuf = rc.readBuf[n:]
		return n, nil
	}

	data, err := rc.recv()
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, io.EOF
	}

	n := copy(b, data)
	if n < len(data) {
		rc.readBuf = data[n:]
	}
	return n, nil
}

// Write implements net.Conn.  Chunks large writes to stay under gRPC limits.
func (rc *RelayConn) Write(b []byte) (int, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.closed {
		return 0, io.ErrClosedPipe
	}

	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > relayMaxChunk {
			chunk = chunk[:relayMaxChunk]
		}
		if err := rc.send(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

// Close implements net.Conn. On the client side it ends the stream's send
// half, as closing a TCP connection sends FIN, so the peer's Read returns
// io.EOF (AwaitPeerClose).
func (rc *RelayConn) Close() error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.closed {
		return nil
	}
	rc.closed = true
	if rc.closeSend != nil {
		return rc.closeSend()
	}
	return nil
}

func (rc *RelayConn) LocalAddr() net.Addr                { return relayAddr("relay-local") }
func (rc *RelayConn) RemoteAddr() net.Addr               { return relayAddr("relay") }
func (rc *RelayConn) SetDeadline(_ time.Time) error      { return nil }
func (rc *RelayConn) SetReadDeadline(_ time.Time) error  { return nil }
func (rc *RelayConn) SetWriteDeadline(_ time.Time) error { return nil }

type relayAddr string

func (a relayAddr) Network() string { return "relay" }
func (a relayAddr) String() string  { return string(a) }
