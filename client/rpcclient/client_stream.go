// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ClientStream is the caller's view of a bidirectional agent-to-agent call.
// It mirrors grpc.ClientStream.
type ClientStream interface {
	// Send sends request data to the target agent. It is not safe to
	// call from several goroutines at once (as grpc.ClientStream's
	// SendMsg): a call has one sender.
	Send(data []byte) error
	// CloseSend signals that no more request messages will be sent.
	// The target agent's ServerStream.Recv will return io.EOF.
	CloseSend() error
	// Recv receives a response from the target agent. Returns io.EOF
	// when the target has finished sending (handler returned).
	Recv() (*Response, error)
	// Header returns the initial metadata sent by the target agent.
	// Blocks until the first response arrives.
	Header() (MD, error)
	// Context returns the call's context.
	Context() context.Context
}

type clientStream struct {
	agent         *Agent
	txnID         string
	targetAgentID string
	sourceAgentID string
	msgType       string
	deadlineMs    int64
	responseCh    chan *pb.TunnelFrame
	done          chan struct{}
	ended         chan struct{} // closed once the call, its context or the agent ended
	ctx           context.Context

	mu         sync.Mutex
	sentFirst  bool
	sendClosed bool

	responseOnce  sync.Once
	responseErrMu sync.RWMutex
	responseErr   error
	headerOnce    sync.Once
	header        MD
	headerCh      chan struct{}
	e2ee          *a2aE2EEState
}

func (cs *clientStream) setResponseError(err error) {
	if err == nil {
		return
	}
	cs.responseErrMu.Lock()
	if cs.responseErr == nil {
		cs.responseErr = err
	}
	cs.responseErrMu.Unlock()
}

func (cs *clientStream) responseError() error {
	cs.responseErrMu.RLock()
	defer cs.responseErrMu.RUnlock()
	return cs.responseErr
}

func (cs *clientStream) closeResponses() {
	cs.responseOnce.Do(func() {
		close(cs.responseCh)
		if cs.done != nil {
			close(cs.done)
		}
	})
}

// pushResponse puts a response into the call's buffer without waiting: a
// data frame is charged to the call's credit, and the caller's credit
// guarantees it room (ResponseWindow, plus a slot for the call's end).
// errPastWindow: the peer sent past the window; errCallEnded: the call ended.
func (cs *clientStream) pushResponse(msg *pb.TunnelFrame) (err error) {
	defer func() {
		if recover() != nil { // closeResponses ran: the call ended
			err = errCallEnded
		}
	}()
	if !msg.GetEom() {
		traceCC(cs.agent, "Deliver", cs.txnID, 0)
		if cs.agent.callCredit.Received(cs.txnID, 1) != nil {
			return errPastWindow
		}
	}
	select {
	case cs.responseCh <- msg:
		return nil
	default:
		return errPastWindow
	}
}

// refuse ends the call with err (its peer broke the credit rules) and
// tells the target to stop.
func (cs *clientStream) refuse(err error) {
	log.Printf("rpcclient: refused transaction %s: %v", cs.txnID, err)
	cs.setResponseError(err)
	cs.closeResponses()
	cs.agent.pending.Delete(cs.txnID)
	go cs.sendCancel() // the receive loop never waits on a send
}

// sendCancel tells the call's target that the caller left (the relay
// forwards it: the target's handler context ends).
func (cs *clientStream) sendCancel() {
	_ = cs.agent.sendFrame(&pb.TunnelFrame{
		MessageType:   "cancel",
		TransactionId: cs.txnID,
		Timestamps:    &pb.Timestamps{RequestAtAgent: time.Now().UnixMilli()},
		Routing:       &pb.RoutingInfo{AgentId: cs.sourceAgentID, TargetAgentId: cs.targetAgentID},
		Eom:           true,
	})
}

// Send transmits data immediately with Eom=false.
func (cs *clientStream) Send(data []byte) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.sendClosed {
		return io.ErrClosedPipe
	}
	if cs.e2ee != nil {
		if err := cs.ensureE2EEHandshake(); err != nil {
			return err
		}
	}
	return cs.sendMsg(data, false)
}

// CloseSend sends an empty EOM frame to signal end of request stream.
func (cs *clientStream) CloseSend() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.sendClosed {
		return nil
	}
	cs.sendClosed = true
	if cs.e2ee != nil {
		if err := cs.ensureE2EEHandshake(); err != nil {
			return err
		}
	}
	return cs.sendMsg(nil, true)
}

func (cs *clientStream) sendMsg(data []byte, eom bool) error {
	// A data frame takes one of the call's credit (the target's
	// RequestWindow); the request's end takes none.
	if !eom && !cs.agent.callCredit.Acquire(cs.txnID, 1) {
		return cs.sendEnded()
	}
	// An E2EE call seals every frame, its end too (END), after its credit:
	// a sealed frame is always sent, so the counters stay in step.
	if cs.e2ee != nil {
		t := a2aFrameData
		if eom {
			t = a2aFrameEnd
		}
		ciphertext, err := cs.e2ee.seal(t, data)
		if err != nil {
			return fmt.Errorf("rpcclient: encrypt request payload: %w", err)
		}
		data = ciphertext
	}
	if eom {
		traceCC(cs.agent, "Eom", cs.txnID, 0)
	} else {
		traceCC(cs.agent, "Send", cs.txnID, 0)
	}

	md := &pb.RoutingInfo{
		AgentId:       cs.sourceAgentID,
		TargetAgentId: cs.targetAgentID,
	}
	if !cs.sentFirst && cs.deadlineMs > 0 {
		md.DeadlineMs = cs.deadlineMs
	}
	// Every frame after the call's start (its first frame, or an E2EE
	// call's handshake) is a continuation: a target no longer serving the
	// call drops it (spec/CallLifecycle.tla AtMostOneCall).
	cont := cs.sentFirst || cs.e2ee != nil
	cs.sentFirst = true

	return cs.agent.sendFrame(&pb.TunnelFrame{
		Payload:       data,
		MessageType:   cs.msgType,
		TransactionId: cs.txnID,
		Timestamps:    &pb.Timestamps{RequestAtAgent: time.Now().UnixMilli()},
		Routing:       md,
		Eom:           eom,
		Continuation:  cont,
	})
}

func (cs *clientStream) ensureE2EEHandshake() error {
	return cs.ensureHandshake(cs.e2ee)
}

func (cs *clientStream) ensureHandshake(s *a2aE2EEState) error {
	return s.ensureClientHandshake(cs.ctx, cs.agent.Done(), func() error {
		return cs.agent.connectionClosed()
	}, func(pub []byte) error {
		return cs.sendControl(a2aE2EEInitMessageType, pub)
	})
}

// sendControl sends one of the call's handshake frames (they carry the
// routing and deadline the call's first frame carries).
func (cs *clientStream) sendControl(messageType string, payload []byte) error {
	return cs.agent.sendFrame(&pb.TunnelFrame{
		Payload:       payload,
		MessageType:   messageType,
		TransactionId: cs.txnID,
		Timestamps:    &pb.Timestamps{RequestAtAgent: time.Now().UnixMilli()},
		Routing: &pb.RoutingInfo{
			AgentId:       cs.sourceAgentID,
			TargetAgentId: cs.targetAgentID,
			DeadlineMs:    cs.deadlineMs,
		},
	})
}

// failE2EE ends the call: its waiting sends and receives get err.
func (cs *clientStream) failE2EE(err error) {
	cs.e2ee.fail(err)
	cs.setResponseError(err)
	cs.closeResponses()
	cs.agent.pending.Delete(cs.txnID)
}

// Recv receives a single response. Returns io.EOF when the target has
// finished sending, ErrConnectionClosed when the agent's relay connection
// closed first, and a gRPC status error if the target returned one.
func (cs *clientStream) Recv() (*Response, error) {
	var msg *pb.TunnelFrame
	var ok bool
	select {
	case <-cs.ctx.Done():
		return nil, cs.ctx.Err()
	case msg, ok = <-cs.responseCh:
	case <-cs.agent.Done():
		// Frames delivered before the connection closed come first.
		select {
		case msg, ok = <-cs.responseCh:
		default:
			return nil, cs.agent.connectionClosed()
		}
	}
	if !ok {
		if err := cs.responseError(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	if !msg.GetEom() {
		traceCC(cs.agent, "Read", cs.txnID, 0)
		cs.agent.callCredit.Consumed(cs.txnID, 1) // may send a window update
	}

	if cs.e2ee != nil {
		return cs.recvE2EE(msg)
	}

	// Error from proxy (e.g., target not connected).
	if msg.GetMessageType() == "error" {
		code := codes.Code(msg.GetStatusCode())
		if code == 0 {
			code = codes.Internal
		}
		return nil, status.Error(code, statusDetail(msg))
	}

	// Status trailer: EOM, its detail in the clear (sent by library after handler returns).
	data := msg.GetPayload()
	if msg.GetEom() {
		code := codes.Code(msg.GetStatusCode())
		if code != 0 && code != codes.OK {
			return nil, status.Error(code, statusDetail(msg))
		}
		if len(data) == 0 {
			return nil, io.EOF
		}
	}

	// Capture initial metadata from first response.
	cs.headerOnce.Do(func() {
		if im := msg.GetRouting().GetInitialMetadata(); len(im) > 0 {
			cs.header = MD(im)
		}
		close(cs.headerCh)
	})

	return &Response{Data: data}, nil
}

func statusDetail(msg *pb.TunnelFrame) string {
	if detail := msg.GetStatusDetail(); detail != "" {
		return detail
	}
	return string(msg.GetPayload())
}

// recvE2EE is Recv of an established E2EE call: a frame in the clear (an
// error, an empty end) is the relay's; a sealed one is the peer's data, end
// or error; one that does not open ends the call.
func (cs *clientStream) recvE2EE(msg *pb.TunnelFrame) (*Response, error) {
	data := msg.GetPayload()
	if msg.GetMessageType() == "error" || len(data) == 0 {
		code := codes.Code(msg.GetStatusCode())
		if code == codes.OK && msg.GetMessageType() == "error" {
			code = codes.Internal
		}
		return nil, errA2AE2EERelayEnded(code, msg.GetStatusDetail())
	}
	t, body, err := cs.e2ee.open(data)
	switch {
	case err != nil:
	case msg.GetEom() && t == a2aFrameEnd:
		return nil, io.EOF
	case msg.GetEom() && t == a2aFrameError:
		code, detail, ok := parseA2AErrorBody(body)
		if ok {
			return nil, status.Error(code, detail)
		}
		err = errors.New("rpcclient: a malformed A2A E2EE error frame")
	case !msg.GetEom() && t == a2aFrameData:
		cs.headerOnce.Do(func() {
			if im := msg.GetRouting().GetInitialMetadata(); len(im) > 0 {
				cs.header = MD(im)
			}
			close(cs.headerCh)
		})
		return &Response{Data: body}, nil
	default:
		err = fmt.Errorf("rpcclient: an A2A E2EE frame of type %d out of place", t)
	}
	err = fmt.Errorf("rpcclient: decrypt response payload: %w", err)
	cs.refuse(err)
	return nil, err
}

// Header returns the initial metadata from the target agent's first response.
// Blocks until the first response arrives or the context is cancelled.
// sendEnded is a Send's error once the call's credit ended: the call's
// context, the agent, or the call itself (its target answered: io.EOF, as
// gRPC's Send after the server's status).
func (cs *clientStream) sendEnded() error {
	if err := cs.ctx.Err(); err != nil {
		return err
	}
	if cs.agent.ctx.Err() != nil {
		return cs.agent.connectionClosed()
	}
	if err := cs.responseError(); err != nil {
		return err
	}
	return io.EOF
}

func (cs *clientStream) Header() (MD, error) {
	select {
	case <-cs.headerCh:
		return cs.header, nil
	case <-cs.ctx.Done():
		return nil, cs.ctx.Err()
	case <-cs.agent.Done():
		return nil, cs.agent.connectionClosed()
	}
}

// Context returns the call's context.
func (cs *clientStream) Context() context.Context {
	return cs.ctx
}
