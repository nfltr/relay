// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ClientStream is the caller's view of a bidirectional agent-to-agent call.
// It mirrors grpc.ClientStream.
type ClientStream interface {
	// Send sends request data to the target agent.
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
	peerLabel     string // the A2AE2EEStaticLabel value the first flight used
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

// Send transmits data immediately with Eom=false.
func (cs *clientStream) Send(data []byte) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.sendClosed {
		return io.ErrClosedPipe
	}
	if cs.e2ee != nil && len(data) > 0 {
		if sent, err := cs.sendFirstFlight(data); sent || err != nil {
			return err
		}
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
	// Nothing follows a 0-RTT first flight until the peer took or refused it.
	if cs.e2ee != nil && cs.e2ee.awaitingHandshake() {
		if err := cs.ensureE2EEHandshake(); err != nil {
			return err
		}
	}
	return cs.sendMsg(nil, true)
}

func (cs *clientStream) sendMsg(data []byte, eom bool) error {
	if cs.e2ee != nil && len(data) > 0 {
		ciphertext, err := cs.e2ee.encrypt(cs.txnID, data)
		if err != nil {
			return fmt.Errorf("rpcclient: encrypt request payload: %w", err)
		}
		data = ciphertext
	}

	md := &pb.RoutingInfo{
		AgentId:       cs.sourceAgentID,
		TargetAgentId: cs.targetAgentID,
	}
	if !cs.sentFirst && cs.deadlineMs > 0 {
		md.DeadlineMs = cs.deadlineMs
	}
	cs.sentFirst = true

	return cs.agent.sendFrame(&pb.TunnelFrame{
		Payload:       data,
		MessageType:   cs.msgType,
		TransactionId: cs.txnID,
		Timestamps:    &pb.Timestamps{RequestAtAgent: time.Now().UnixMilli()},
		Routing:       md,
		Eom:           eom,
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

// sendFirstFlight sends data as the 0-RTT first flight when the call knows
// the peer's static key and has sent nothing; sent is false otherwise.
func (cs *clientStream) sendFirstFlight(data []byte) (sent bool, err error) {
	payload, ok, err := cs.e2ee.firstFlight(data, time.Now(), rand.Reader)
	if !ok {
		return false, nil
	}
	if err == nil {
		cs.sentFirst = true
		err = cs.sendControl(a2aE2EEInit0RTTMessageType, payload)
	}
	if err != nil {
		err = fmt.Errorf("rpcclient: send A2A E2EE 0-RTT first flight: %w", err)
		cs.e2ee.fail(err)
	}
	return true, err
}

// onE2EERetry handles the peer's refusal of the first flight: the
// interactive handshake on the same call, then the request again, before
// anything else of the call is sent. A refusal that must not be retried
// ends the call.
func (cs *clientStream) onE2EERetry(payload []byte) {
	inner, early, reason, err := cs.e2ee.takeRetry(payload, time.Now())
	if err != nil {
		cs.failE2EE(status.Error(codes.FailedPrecondition, err.Error()))
		return
	}
	if inner == nil {
		return
	}
	if reason == refuseStale {
		forgetA2AE2EEPeer(cs.targetAgentID, cs.peerLabel)
	}
	go func() {
		err := cs.ensureHandshake(inner)
		if err == nil {
			err = cs.resendEarly(inner, early)
		}
		if err == nil {
			err = cs.e2ee.adopt(inner)
		}
		if err != nil {
			cs.failE2EE(err)
		}
	}()
}

func (cs *clientStream) resendEarly(s *a2aE2EEState, data []byte) error {
	ciphertext, err := s.encrypt(cs.txnID, data)
	if err != nil {
		return err
	}
	return cs.agent.sendFrame(&pb.TunnelFrame{
		Payload:       ciphertext,
		MessageType:   cs.msgType,
		TransactionId: cs.txnID,
		Timestamps:    &pb.Timestamps{RequestAtAgent: time.Now().UnixMilli()},
		Routing:       &pb.RoutingInfo{AgentId: cs.sourceAgentID, TargetAgentId: cs.targetAgentID},
	})
}

// failE2EE ends the call: its waiting sends and receives get err.
func (cs *clientStream) failE2EE(err error) {
	cs.e2ee.fail(err)
	cs.setResponseError(err)
	cs.closeResponses()
	cs.agent.pending.Delete(cs.txnID)
}

func (cs *clientStream) statusDetail(msg *pb.TunnelFrame) string {
	if detail := msg.GetStatusDetail(); detail != "" {
		return detail
	}
	data := msg.GetPayload()
	if len(data) == 0 {
		return ""
	}
	if cs.e2ee != nil {
		plaintext, err := cs.e2ee.decrypt(cs.txnID, data)
		if err == nil {
			return string(plaintext)
		}
	}
	return string(data)
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

	// Error from proxy (e.g., target not connected).
	if msg.GetMessageType() == "error" {
		code := codes.Code(msg.GetStatusCode())
		if code == 0 {
			code = codes.Internal
		}
		return nil, status.Error(code, cs.statusDetail(msg))
	}

	// Status trailer: EOM with optional encrypted detail (sent by library after handler returns).
	data := msg.GetPayload()
	if msg.GetEom() {
		code := codes.Code(msg.GetStatusCode())
		if code != 0 && code != codes.OK {
			return nil, status.Error(code, cs.statusDetail(msg))
		}
		if len(data) == 0 {
			return nil, io.EOF
		}
	}

	if cs.e2ee != nil && len(data) > 0 {
		plaintext, err := cs.e2ee.decrypt(cs.txnID, data)
		if err != nil {
			return nil, fmt.Errorf("rpcclient: decrypt response payload: %w", err)
		}
		data = plaintext
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

// Header returns the initial metadata from the target agent's first response.
// Blocks until the first response arrives or the context is cancelled.
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
