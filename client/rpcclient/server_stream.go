// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/relay/client/handoff"
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
	early      []byte // a 0-RTT call's first request, already decrypted
}

// consumerStall bounds how long the tunnel's receive loop, which serves
// every call and response of the agent, waits for one consumer (a
// handler's call, a caller's response stream) to take anything of its
// transaction (handoff.Stall; tests shorten it).
var consumerStall = handoff.Stall

// pushRequest enqueues a request frame onto ss.requestCh, skipping the
// send if the channel has already been closed (the EOM marker arrived
// from a concurrent code path). It waits for a full channel only while
// the handler keeps taking, at most consumerStall (handoff.Send): then
// handoff.ErrStalled, and the caller refuses the call. A call that ended
// is handoff.ErrEnded, the frame dropped.
func (ss *serverStream) pushRequest(msg *pb.TunnelFrame) (err error) {
	if ss == nil || ss.closed.Load() {
		return handoff.ErrEnded
	}
	defer func() {
		// Belt-and-braces: another goroutine may have closed between the
		// flag check and the actual send. The panic that would otherwise
		// reach the runtime is swallowed: the message is then equivalent
		// to "arrived after close" and is correctly dropped.
		if recover() != nil {
			err = handoff.ErrEnded
		}
	}()
	return handoff.Send(ss.requestCh, msg, ss.ctx.Done(), consumerStall)
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
	ss.mu.Lock()
	early := ss.early
	ss.early = nil
	ss.mu.Unlock()
	if early != nil {
		return early, nil
	}
	select {
	case msg, ok := <-ss.requestCh:
		if !ok {
			return nil, io.EOF
		}
		data := msg.GetPayload()
		// Empty-data EOM is the CloseSend marker — return EOF.
		if msg.GetEom() && len(data) == 0 {
			return nil, io.EOF
		}
		if ss.e2ee != nil && len(data) > 0 {
			plaintext, err := ss.e2ee.decrypt(ss.txnID, data)
			if err != nil {
				return nil, fmt.Errorf("rpcclient: decrypt request payload: %w", err)
			}
			data = plaintext
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
	if !ss.headerSent {
		header := ss.header
		if ss.e2ee != nil {
			header = withA2AE2EEHeaders(header)
		}
		if header != nil {
			md.InitialMetadata = map[string]string(header)
		}
		ss.headerSent = true
	}
	ss.mu.Unlock()

	if ss.e2ee != nil && len(data) > 0 {
		ciphertext, err := ss.e2ee.encrypt(ss.txnID, data)
		if err != nil {
			return fmt.Errorf("rpcclient: encrypt response payload: %w", err)
		}
		data = ciphertext
	}

	return ss.agent.sendFrame(&pb.TunnelFrame{
		Payload:       data,
		MessageType:   "a2a-response",
		TransactionId: ss.txnID,
		Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
		Routing:       md,
	})
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
