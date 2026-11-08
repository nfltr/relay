// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/relay/proto/pb"
)

// ServerStream is the handler's view of an incoming agent-to-agent call.
// It mirrors grpc.ServerStream.
type ServerStream interface {
	// Recv receives the next request message. Returns io.EOF after the
	// last request message (when the source called CloseSend).
	Recv() ([]byte, error)
	// Send sends a response message to the source agent.
	Send(data []byte) error
	// SetHeader sets initial metadata to be sent with the first response.
	// Must be called before the first Send.
	SetHeader(md MD)
	// Context returns the call's context. It is cancelled when the source
	// agent cancels the call or the Agent is closed.
	Context() context.Context
	// SourceAgentID returns the AgentID of the agent that initiated the call.
	SourceAgentID() string
}

type serverStream struct {
	agent         *Agent
	txnID         string
	sourceAgentID string
	sourceSession uint64 // RoutingInfo.source_session of the call's first frame
	ctx           context.Context
	cancel        context.CancelFunc
	requestCh     chan *pb.TunnelFrame

	// 2026-05-24 deflake (TestNotifyWatchStreams panic: send on closed
	// channel): requestCh can be closed from one goroutine (handleMessage's
	// EOM branch) while another goroutine is still in the
	// `case ss.requestCh <- msg:` send. Guard the close with sync.Once
	// + an atomic flag and route all writes through pushRequest so the
	// send is skipped after close.
	closed    atomic.Bool
	closeOnce sync.Once

	mu         sync.Mutex
	header     MD
	headerSent bool
	e2ee       *a2aE2EEState
}

// errCallEnded: a frame for a call that ended (it is dropped).
var errCallEnded = errors.New("rpcclient: the call ended")

// pushRequest puts a request into the call's buffer without waiting: a
// data frame is charged to the call's credit, which guarantees it room
// (RequestWindow, plus a slot for the request's end). errPastWindow: the
// caller sent past the window; errCallEnded: the call ended.
func (ss *serverStream) pushRequest(msg *pb.TunnelFrame) (err error) {
	if ss == nil || ss.closed.Load() {
		return errCallEnded
	}
	defer func() {
		if recover() != nil { // closeRequests ran
			err = errCallEnded
		}
	}()
	if !msg.GetEom() {
		traceCC(ss.agent, "Deliver", ss.txnID, 0)
		if ss.agent.serveCredit.Received(ss.txnID, 1) != nil {
			return errPastWindow
		}
	}
	select {
	case ss.requestCh <- msg:
		return nil
	default:
		return errPastWindow
	}
}

// closeRequests closes requestCh exactly once. Safe to call from any
// goroutine, any number of times.
func (ss *serverStream) closeRequests() {
	if ss == nil {
		return
	}
	ss.closeOnce.Do(func() {
		ss.closed.Store(true)
		close(ss.requestCh)
	})
}

// Recv returns the next request message's data. Returns io.EOF after the
// source has called CloseSend (all request messages consumed).
func (ss *serverStream) Recv() ([]byte, error) {
	select {
	case msg, ok := <-ss.requestCh:
		if !ok {
			return nil, io.EOF
		}
		if !msg.GetEom() {
			traceCC(ss.agent, "Read", ss.txnID, 0)
			ss.agent.serveCredit.Consumed(ss.txnID, 1) // may send a window update
		}
		data := msg.GetPayload()
		if ss.e2ee != nil {
			return ss.recvE2EE(msg)
		}
		// Empty-data EOM is the CloseSend marker — return EOF.
		if msg.GetEom() && len(data) == 0 {
			return nil, io.EOF
		}
		return data, nil
	case <-ss.ctx.Done():
		return nil, ss.ctx.Err()
	}
}

// Send sends a response message to the source agent. The first Send includes
// any metadata set via SetHeader.
func (ss *serverStream) Send(data []byte) error {
	ss.mu.Lock()
	md := &pb.RoutingInfo{AgentId: ss.agent.agentID}
	t, body := a2aFrameData, data
	if !ss.headerSent {
		header := ss.header
		switch {
		case ss.e2ee != nil: // sealed with the first data: the relay sees no header
			var err error
			t = a2aFrameHeader
			if body, err = a2aHeaderBody(withA2AE2EEHeaders(header), data); err != nil {
				ss.mu.Unlock()
				return fmt.Errorf("rpcclient: encode response headers: %w", err)
			}
		case header != nil:
			md.InitialMetadata = map[string]string(header)
		}
		ss.headerSent = true
	}
	ss.mu.Unlock()

	// One of the call's credit (the caller's ResponseWindow): a caller
	// that stops reading holds this handler, never the agent's other calls.
	if !ss.agent.serveCredit.Acquire(ss.txnID, 1) {
		if err := ss.ctx.Err(); err != nil {
			return err
		}
		return ss.agent.connectionClosed()
	}
	if ss.e2ee != nil { // sealed after its credit: a sealed frame is sent
		ciphertext, err := ss.e2ee.seal(t, body)
		if err != nil {
			return fmt.Errorf("rpcclient: encrypt response payload: %w", err)
		}
		data = ciphertext
	}
	traceCC(ss.agent, "Send", ss.txnID, 0)

	return ss.agent.sendFrame(&pb.TunnelFrame{
		Payload:       data,
		MessageType:   "a2a-response",
		TransactionId: ss.txnID,
		Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
		Routing:       md,
	})
}

// recvE2EE is Recv of an E2EE call's request frame: an empty end is the
// relay's, a sealed one the caller's data or end; one that does not open
// ends the call.
func (ss *serverStream) recvE2EE(msg *pb.TunnelFrame) ([]byte, error) {
	if len(msg.GetPayload()) == 0 {
		return nil, errors.New("rpcclient: the relay ended the request stream (not the caller's end, not end-to-end authenticated)")
	}
	t, body, err := ss.e2ee.open(msg.GetPayload())
	switch {
	case err != nil:
	case msg.GetEom() && t == a2aFrameEnd:
		return nil, io.EOF
	case !msg.GetEom() && t == a2aFrameData:
		return body, nil
	default:
		err = fmt.Errorf("rpcclient: an A2A E2EE frame of type %d out of place", t)
	}
	return nil, fmt.Errorf("rpcclient: decrypt request payload: %w", err)
}

// SetHeader stores initial metadata to include with the first response
// message. Must be called before the first Send.
func (ss *serverStream) SetHeader(md MD) {
	ss.mu.Lock()
	ss.header = md
	ss.mu.Unlock()
}

// Context returns the call's context.
func (ss *serverStream) Context() context.Context {
	return ss.ctx
}

// SourceAgentID returns the AgentID of the agent that initiated this call.
func (ss *serverStream) SourceAgentID() string {
	return ss.sourceAgentID
}

// SourceSession is the relay's number of the connection of the source agent
// that made the call (pb.RoutingInfo source_session): two calls from one
// connection carry one number, a reconnect's calls another; 0 when the
// relay does not number them or stream is not an rpcclient stream. A
// relay's own service applies a call only to the connection that made it.
func SourceSession(stream ServerStream) uint64 {
	if ss, ok := stream.(*serverStream); ok {
		return ss.sourceSession
	}
	return 0
}
