// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nfnet

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nfltr/relay/client/dgram"
	"github.com/nfltr/relay/proto/wire/agentservices"
)

// Datagram services (nfltr docs/decisions/nf1-udp-2026-11-14.md, SDK):
// one session per target carries an association (client/dgram) of flows.

// DatagramConn is one flow: a net.Conn with message semantics (each Write
// one datagram, each Read one; a datagram larger than the buffer is
// dropped with io.ErrShortBuffer) and a net.PacketConn whose WriteTo
// ignores the address (one peer): quic.Dial(ctx, c, c.RemoteAddr(), ...).
type DatagramConn = dgram.Conn

// DialDatagram opens a flow to target's udp service, on the Dialer's
// association to target (opened by the first flow, as Dial opens a
// session; one per target and Plain). Direct paths and Early do not apply
// yet (lane UDP3).
func (d *Dialer) DialDatagram(ctx context.Context, target string, o DialOptions) (*DatagramConn, error) {
	t, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}
	if o.Direct != DirectOff || o.Early {
		return nil, usage("DialDatagram: direct paths and Early are not served for datagram services yet")
	}
	t.datagram = true
	key := target
	if o.Plain {
		key += " plain"
	}
	d.mu.Lock()
	a := d.assocs[key]
	d.mu.Unlock()
	if a != nil {
		if c, err := a.Dial(Addr{Target: "flow"}, Addr{Target: target}); err == nil {
			return c, nil
		}
	}
	c, err := d.DialTarget(ctx, t, o)
	if err != nil {
		return nil, err
	}
	// ponytail: two first dials of one target race to two associations,
	// the loser's ends at its AssocIdle; a per-key once if that matters.
	a = dgram.NewClient(c, dgram.Config{})
	d.mu.Lock()
	if d.assocs == nil {
		d.assocs = map[string]*dgram.Client{}
	}
	d.assocs[key] = a
	d.mu.Unlock()
	return a.Dial(c.LocalAddr(), Addr{Target: target})
}

// PacketListener serves one udp service: every flow of every association
// to it as one net.PacketConn. ReadFrom returns a datagram and the flow's
// Addr{Target: the caller's machine, Flow: its number}; WriteTo(Addr)
// sends on that flow (a closed flow: net.ErrClosed). A DNS server's
// PacketConn or quic.Listen runs on it unchanged.
type PacketListener struct {
	l           *Listener
	inbox, post *dgram.Conn // the flows' datagrams, each prefixed with its flow number

	mu    sync.Mutex
	flows map[uint64]*dgram.Conn
	next  uint64
}

// ListenPacket connects an agent named cfg.Agent serving the udp service
// service, as Listen does a tcp one.
func ListenPacket(ctx context.Context, cfg Config, service string, o ListenOptions) (*PacketListener, error) {
	if o.Direct != DirectOff {
		return nil, usage("ListenPacket: direct paths are not served for datagram services yet")
	}
	l, err := listen(ctx, cfg, service, o, agentservices.UDP)
	if err != nil {
		return nil, err
	}
	p := &PacketListener{l: l, flows: map[uint64]*dgram.Conn{}}
	p.inbox, p.post = dgram.Pipe(4096, l.addr, l.addr)
	go p.accept()
	return p, nil
}

func (p *PacketListener) accept() {
	for {
		c, err := p.l.Accept()
		if err != nil {
			_ = p.inbox.Close()
			return
		}
		from := c.RemoteAddr().String()
		go func() {
			_ = dgram.Serve(context.Background(), c, dgram.Config{}, func() (net.Conn, error) { return p.flow(from), nil })
		}()
	}
}

// flow is a new flow's target: one end of a pipe whose other end feeds
// the inbox and takes WriteTo.
func (p *PacketListener) flow(from string) net.Conn {
	p.mu.Lock()
	p.next++
	id := p.next
	target, mine := dgram.Pipe(64, Addr{Target: from, Flow: id}, p.l.addr)
	p.flows[id] = mine
	p.mu.Unlock()
	go func() {
		buf := make([]byte, 8+dgram.MaxDatagram)
		for {
			n, err := mine.Read(buf[8:])
			if err != nil {
				break
			}
			binary.BigEndian.PutUint64(buf, id)
			_, _ = p.post.Write(buf[:8+n])
		}
		p.mu.Lock()
		delete(p.flows, id)
		p.mu.Unlock()
	}()
	return target
}

// ReadFrom returns the next datagram of any flow.
func (p *PacketListener) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 8+dgram.MaxDatagram) // ponytail: one buffer per read; pool it if a profile says so
	n, err := p.inbox.Read(buf)
	if err != nil {
		if err == io.EOF {
			err = net.ErrClosed
		}
		return 0, nil, err
	}
	id := binary.BigEndian.Uint64(buf)
	var from net.Addr = Addr{Flow: id}
	p.mu.Lock()
	if f := p.flows[id]; f != nil {
		from = f.RemoteAddr()
	}
	p.mu.Unlock()
	if n-8 > len(b) {
		return 0, from, io.ErrShortBuffer
	}
	return copy(b, buf[8:n]), from, nil
}

// WriteTo sends b on the flow addr names (an Addr of ReadFrom).
func (p *PacketListener) WriteTo(b []byte, addr net.Addr) (int, error) {
	a, ok := addr.(Addr)
	if !ok {
		return 0, &net.AddrError{Err: "not an nfnet flow", Addr: addr.String()}
	}
	p.mu.Lock()
	f := p.flows[a.Flow]
	p.mu.Unlock()
	if f == nil {
		return 0, net.ErrClosed
	}
	return f.Write(b)
}

// Close ends the listener's agent and every association.
func (p *PacketListener) Close() error {
	_ = p.inbox.Close()
	return p.l.Close()
}

func (p *PacketListener) LocalAddr() net.Addr                { return p.l.addr }
func (p *PacketListener) SetDeadline(t time.Time) error      { return p.inbox.SetReadDeadline(t) }
func (p *PacketListener) SetReadDeadline(t time.Time) error  { return p.inbox.SetReadDeadline(t) }
func (p *PacketListener) SetWriteDeadline(t time.Time) error { return nil }
