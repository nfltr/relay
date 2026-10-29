// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// RelayBind implements wireguard-go's conn.Bind interface, routing WireGuard
// UDP packets through an in-process byte channel instead of real UDP sockets.
// This allows WireGuard traffic to be relayed over gRPC streams (ConnectHTTP)
// where direct UDP connectivity is unavailable.
//
// Each packet carries the peer tag of its synthetic endpoint: an exit has one
// peer per client and tags packets with the client's public key (the relay
// routes by it); a client has one peer, the exit, and ignores the tag.
//
// Usage:
//
//	bind := NewRelayBind()
//	// Start tunnel with this bind
//	tunnel.Start(ctx, cfg, bind)
//	// Feed incoming encrypted WG packets (from gRPC stream):
//	bind.Deliver(peer, packet)
//	// Read outgoing encrypted WG packets (to send via gRPC stream):
//	pkt := <-bind.Outbound() // pkt.Peer, pkt.Data
type RelayBind struct {
	mu       sync.Mutex
	closed   bool
	inbound  chan relayPacket
	outbound chan Packet
}

// Packet is a sealed WireGuard packet and the peer tag of its endpoint.
type Packet struct {
	Peer string
	Data []byte
}

type relayPacket struct {
	data []byte
	ep   conn.Endpoint
}

// relayEndpoint is a synthetic conn.Endpoint naming one relay peer.
type relayEndpoint struct {
	peer string
}

func (e *relayEndpoint) ClearSrc()           {}
func (e *relayEndpoint) SrcToString() string { return "" }
func (e *relayEndpoint) DstToString() string { return e.peer }
func (e *relayEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// DstIP is one address for every relay peer (wireguard-go rate limits by it).
// allow:wrapper — conn.Endpoint method.
func (e *relayEndpoint) DstIP() netip.Addr  { return netip.AddrFrom4([4]byte{127, 0, 0, 1}) }
func (e *relayEndpoint) DstToBytes() []byte { return []byte(e.peer) }

// NewRelayBind creates a new RelayBind for relaying WireGuard packets.
func NewRelayBind() *RelayBind {
	return &RelayBind{
		inbound:  make(chan relayPacket, 256),
		outbound: make(chan Packet, 256),
	}
}

// Deliver feeds an incoming encrypted WireGuard packet from the named peer
// into the tunnel. Called by the gRPC stream reader when it receives
// WG-encrypted bytes from the remote peer. WireGuard authenticates the packet
// itself; the tag only lets replies carry the same tag back.
func (b *RelayBind) Deliver(peer string, data []byte) error {
	pkt := relayPacket{data: make([]byte, len(data)), ep: &relayEndpoint{peer: peer}}
	copy(pkt.data, data)

	// Hold mu across the (non-blocking) send so Close cannot close the
	// channel under it.
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return net.ErrClosed
	}
	select {
	case b.inbound <- pkt:
		return nil
	default:
		return errors.New("wg: relay inbound buffer full")
	}
}

// Outbound returns the channel from which outgoing encrypted WireGuard
// packets can be read.  The caller should forward these bytes to the remote
// peer via the gRPC stream.
func (b *RelayBind) Outbound() <-chan Packet {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.outbound
}

// DropQueued discards the outgoing packets no stream has read and returns how
// many. A client that keeps its tunnel across relay sessions calls it before
// relaying a new session: what WireGuard queued while no session was up
// (handshake initiations for dead handshake state) would otherwise reach the
// exit ahead of the fresh initiation, which the exit then rejects as a flood
// (G-R3).
func (b *RelayBind) DropQueued() int {
	out := b.Outbound()
	for n := 0; ; n++ {
		select {
		case _, ok := <-out:
			if !ok {
				return n
			}
		default:
			return n
		}
	}
}

// ---------------------------------------------------------------------------
// conn.Bind interface
// ---------------------------------------------------------------------------

// Open starts the relay bind.  The port parameter is ignored since we don't
// bind to a real UDP socket.
//
// wireguard-go calls Close() then Open() during device.Up() (BindUpdate),
// so the bind must be re-openable after close.  We recreate channels on
// each Open() call.
func (b *RelayBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Recreate channels — allows reopen after Close().
	b.inbound = make(chan relayPacket, 256)
	b.outbound = make(chan Packet, 256)
	b.closed = false

	inbound := b.inbound // capture for closure

	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		pkt, ok := <-inbound
		if !ok {
			return 0, net.ErrClosed
		}
		n := copy(packets[0], pkt.data)
		sizes[0] = n
		eps[0] = pkt.ep
		return 1, nil
	}

	return []conn.ReceiveFunc{recv}, 51820, nil
}

// Close stops the relay bind and drains channels.
// wireguard-go calls Close() before Open() during BindUpdate, so this
// must be safe to call multiple times and the bind must be re-openable.
func (b *RelayBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true
	close(b.inbound)
	close(b.outbound)
	return nil
}

// SetMark is a no-op for relay (no real socket).
func (b *RelayBind) SetMark(mark uint32) error { return nil }

// Send writes encrypted WireGuard packets to the outbound channel for relay.
func (b *RelayBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	// Hold mu across the (non-blocking) sends so Close cannot close the
	// channel under them.
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return net.ErrClosed
	}

	var peer string
	if rep, ok := ep.(*relayEndpoint); ok {
		peer = rep.peer
	}
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		pkt := Packet{Peer: peer, Data: make([]byte, len(buf))}
		copy(pkt.Data, buf)
		select {
		case b.outbound <- pkt:
		default:
			return errors.New("wg: relay outbound buffer full")
		}
	}
	return nil
}

// ParseEndpoint makes the endpoint for a peer tag (IPC endpoint=<tag>).
func (b *RelayBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &relayEndpoint{peer: s}, nil
}

// BatchSize returns 1 since relay processes one packet at a time.
func (b *RelayBind) BatchSize() int { return 1 }
