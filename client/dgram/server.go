// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
)

// Dial connects one flow's socket to the service's target (a connected UDP
// socket, or one in the process). It is called from the association's
// reader, so it must not wait: resolve the target's address beforehand.
type Dial func() (net.Conn, error)

// Server is the agent's side of one association.
type Server struct{ a *assoc }

// Serve runs the agent's side of an association on stream until it ends
// (the peer's end, ctx, a protocol error): each flow the client opens gets
// its own socket from dial. It returns why the association ended (io.EOF
// at the client's clean end) and closes stream.
func Serve(ctx context.Context, stream io.ReadWriteCloser, cfg Config, dial Dial) error {
	s := NewServer(stream, cfg, dial)
	stop := context.AfterFunc(ctx, func() { s.a.end(ctx.Err()) })
	defer stop()
	<-s.a.done
	return s.a.errNow()
}

// NewServer runs the agent's side of an association on stream in the
// background (Serve's); Done and Close are its end.
func NewServer(stream io.ReadWriteCloser, cfg Config, dial Dial) *Server {
	s := &Server{a: newAssoc(stream, cfg, false)}
	go s.a.send()
	go s.a.read(func(f frame) error { return s.handle(f, dial) })
	go s.a.sweep(func(f *flow) { s.closeFlow(f, ReasonBackstop) })
	return s
}

// Stats are the association's counters.
func (s *Server) Stats() Stats { return s.a.stats() }

// Done is closed when the association ended.
func (s *Server) Done() <-chan struct{} { return s.a.done }

// Close ends the association (a revocation: nothing reaches a target
// after it returns).
func (s *Server) Close() error {
	s.a.end(net.ErrClosed)
	return nil
}

func (s *Server) handle(fr frame, dial Dial) error {
	a := s.a
	a.mu.Lock()
	defer a.mu.Unlock()
	switch fr.typ {
	case frameOpen:
		return s.open(fr, dial)
	case frameData, frameClose:
		if fr.id > a.high {
			return fmt.Errorf("%w: frame %q for flow %d not opened", ErrProtocol, fr.typ, fr.id)
		}
		f := a.flows[fr.id]
		if fr.typ == frameClose {
			traceRecvA("close", fr.id, "")
			if f != nil {
				s.drop(f)
			}
			return nil
		}
		if f == nil {
			traceRecvA("d", fr.id, "drop")
			a.cnt.closed.Add(1)
			return nil
		}
		traceRecvA("d", fr.id, "deliver")
		f.touch()
		select {
		case f.in <- append([]byte(nil), fr.payload...):
			a.cnt.in.Add(1)
		default:
			a.cnt.targetFull.Add(1)
		}
		return nil
	}
	return fmt.Errorf("%w: frame %q from the client", ErrProtocol, fr.typ)
}

// open answers an O (a.mu held): refused at or below the highest id seen,
// past MaxFlows or when the target cannot be dialled; else the flow's
// socket, its first datagram written.
func (s *Server) open(fr frame, dial Dial) error {
	a := s.a
	refuse := func(why Reason) error {
		traceRecvA("open", fr.id, "refuse")
		a.cnt.refused.Add(1)
		a.enqueue(frame{typ: frameRefuse, id: fr.id, reason: why}, nil)
		return nil
	}
	if fr.id <= a.high {
		return refuse(ReasonClosed)
	}
	a.high = fr.id
	if len(a.flows) >= a.cfg.MaxFlows {
		a.cnt.flowsFull.Add(1)
		return refuse(ReasonFull)
	}
	conn, err := dial()
	if err != nil {
		return refuse(ReasonUnreachable)
	}
	f := &flow{id: fr.id, state: stOpen, conn: conn, in: make(chan []byte, a.cfg.QueueLen)}
	f.touch()
	a.flows[f.id] = f
	a.cnt.flows.Add(1)
	traceRecvA("open", fr.id, "accept")
	a.enqueue(frame{typ: frameAccept, id: fr.id}, nil)
	f.in <- append([]byte(nil), fr.payload...)
	a.cnt.in.Add(1)
	go s.write(f)
	go s.replies(f)
	return nil
}

// write writes the flow's datagrams to its target: a datagram too large
// for the path is a counted drop, never a retry; another failure closes
// the flow (ReasonTarget). At the flow's close it writes what the flow
// took before, then closes the socket (the association's end closes it at
// once: nothing reaches the target after a revocation).
func (s *Server) write(f *flow) {
	defer f.conn.Close()
	for p := range f.in {
		if _, err := f.conn.Write(p); err != nil {
			if errors.Is(err, syscall.EMSGSIZE) {
				s.a.cnt.tooLarge.Add(1)
				continue
			}
			s.closeFlow(f, ReasonTarget)
		}
	}
}

// replies reads the target's datagrams onto the stream (each in the
// flow's queue bound, else dropped) until the socket closes.
func (s *Server) replies(f *flow) {
	buf := make([]byte, MaxDatagram)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			s.closeFlow(f, ReasonTarget)
			return
		}
		a := s.a
		a.mu.Lock()
		if f.state == stOpen && a.enqueue(frame{typ: frameData, id: f.id, payload: buf[:n]}, f) {
			traceReplyA(f.id)
			a.cnt.out.Add(1)
		}
		a.mu.Unlock()
	}
}

// closeFlow closes f (its socket) and tells the client.
func (s *Server) closeFlow(f *flow, why Reason) {
	a := s.a
	a.mu.Lock()
	defer a.mu.Unlock()
	if f.state == stClosed {
		return
	}
	if a.enqueue(frame{typ: frameClose, id: f.id, reason: why}, nil) {
		traceExpireA(f.id)
	}
	s.drop(f)
}

// drop forgets f (a.mu held); its writer closes its socket.
func (s *Server) drop(f *flow) {
	s.a.remove(f)
	close(f.in)
}
