// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
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
	stop := context.AfterFunc(ctx, func() { s.a.endWith(ctx.Err(), 0, endCut) })
	defer stop()
	<-s.a.done
	return s.a.errNow()
}

// NewServer runs the agent's side of an association on stream in the
// background (Serve's); Done and Close are its end.
func NewServer(stream io.ReadWriteCloser, cfg Config, dial Dial) *Server {
	s := &Server{a: newAssoc(stream, cfg, false)}
	traceServe(s.a.cfg.MaxFlows)
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
// after it returns). A second Close returns nil (TestCloseTwice).
func (s *Server) Close() error {
	s.a.endWith(net.ErrClosed, 0, endRevoke)
	return nil
}

// CloseWith is Close that tells the client why each open flow ended (its
// Closed gets why): ReasonRevoked for a revocation, ReasonClosed for the
// service's stop. Nothing reaches a target after it returns either.
func (s *Server) CloseWith(why Reason) {
	s.a.endWith(net.ErrClosed, why, endRevoke)
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
			a.add(cClosed, 1)
			return nil
		}
		traceRecvA("d", fr.id, "deliver")
		f.touch()
		s.toTarget(f, fr.payload)
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
		a.add(cRefused, 1)
		a.enqueue(frame{typ: frameRefuse, id: fr.id, reason: why}, nil)
		return nil
	}
	if fr.id <= a.high {
		return refuse(ReasonClosed)
	}
	a.high = fr.id
	if len(a.flows) >= a.cfg.MaxFlows || a.svc != nil && !a.svc.take() {
		a.add(cFlowsFull, 1)
		return refuse(ReasonFull)
	}
	conn, err := dial()
	if err != nil {
		if a.svc != nil {
			a.svc.live.Add(-1)
		}
		return refuse(ReasonUnreachable)
	}
	f := &flow{id: fr.id, state: stOpen, conn: conn, in: make(chan []byte, a.cfg.QueueLen)}
	f.touch()
	a.flows[f.id] = f
	a.add(cFlows, 1)
	traceRecvA("open", fr.id, "accept")
	a.enqueue(frame{typ: frameAccept, id: fr.id}, nil)
	s.toTarget(f, fr.payload)
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
		_, err := f.conn.Write(p)
		f.inBytes.Add(-int64(len(p)))
		if err != nil {
			if errors.Is(err, syscall.EMSGSIZE) {
				s.a.add(cTooLarge, 1)
				continue
			}
			s.closeFlow(f, ReasonTarget)
		}
	}
}

// toTarget queues p for f's target (a.mu held): within the flow's
// QueueLen datagrams and QueueBytes bytes (a stalled target holds at most
// that), else a counted drop (TargetFull), never a wait.
func (s *Server) toTarget(f *flow, p []byte) {
	a := s.a
	if f.inBytes.Load()+int64(len(p)) > int64(a.cfg.QueueBytes) {
		a.add(cTargetFull, 1)
		return
	}
	select {
	case f.in <- append([]byte(nil), p...):
		f.inBytes.Add(int64(len(p)))
		a.add(cIn, 1)
	default:
		a.add(cTargetFull, 1)
	}
}

// Service is what every association of one udp service shares at the
// agent (Config.Service): a bound on their flows together, so a service
// holds at most MaxFlows sockets however many associations its clients
// open, and their counters together. An open past it is refused (R,
// ReasonFull) and counted FlowsFull, as one past an association's own
// MaxFlows. Use one Service per service for the process's lifetime.
type Service struct {
	// MaxFlows bounds the flows open at once across the associations
	// (DefaultServiceFlows when zero).
	MaxFlows int
	live     atomic.Int64
	cnt      counters
}

// DefaultServiceFlows is a Service's default MaxFlows: four associations
// at their own default cap.
const DefaultServiceFlows = 1024

// take claims a flow's place; false when the service is full.
func (v *Service) take() bool {
	max := int64(v.MaxFlows)
	if max <= 0 {
		max = DefaultServiceFlows
	}
	if v.live.Add(1) > max {
		v.live.Add(-1)
		return false
	}
	return true
}

// Stats are the counters of every association of the service so far
// (Live: the flows open now across them).
func (v *Service) Stats() Stats { return v.cnt.stats(int(v.live.Load())) }

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
			if a.direct == nil {
				traceReplyA(f.id) // else its sender's, with its carrier (traceSend)
			}
			a.add(cOut, 1)
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
