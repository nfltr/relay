// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"encoding/binary"
	"log"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Per-call credit (spec/CallCredit.tla; spec/README.md "CallCredit.tla" is
// the design). A call's sender takes one credit per data frame; the
// receiver's receive loop, which serves every call on the connection, puts
// each frame into its call's buffer without waiting (credit guarantees
// room) and the app's Recv grants it back in window updates. So a caller or
// handler that stops reading holds only its own call, never the loop.
const (
	// ResponseWindow is how many response frames of one call a caller
	// buffers: a handler sends at most that many ahead of the caller's reads.
	ResponseWindow = 256
	// RequestWindow is how many request frames of one call a handler
	// buffers.
	RequestWindow = 16
	// WindowMessageType is a window update: the call's transaction id and,
	// as an unsigned varint payload, how many more frames its peer may send.
	WindowMessageType = "a2a-window"
)

// newCallCredits makes the agent's two credits: calls it makes (it buffers
// responses, the peer requests) and calls it serves (the other way round).
func (a *Agent) newCallCredits() {
	a.callCredit = link.NewCredit(ResponseWindow, RequestWindow, a.grantCall)
	a.serveCredit = link.NewCredit(RequestWindow, ResponseWindow, a.grantServed)
}

// grantCall sends the target of a call this agent made a window update
// for n responses (routed like the call's requests).
func (a *Agent) grantCall(txnID string, n int) {
	val, ok := a.pending.Load(txnID)
	if !ok {
		return
	}
	cs := val.(*clientStream)
	a.sendWindow(txnID, n, &pb.RoutingInfo{AgentId: cs.sourceAgentID, TargetAgentId: cs.targetAgentID})
}

// grantServed sends the caller of a call this agent serves a window update
// for n requests (routed like the call's responses).
func (a *Agent) grantServed(txnID string, n int) {
	a.sendWindow(txnID, n, &pb.RoutingInfo{AgentId: a.agentID})
}

func (a *Agent) sendWindow(txnID string, n int, routing *pb.RoutingInfo) {
	err := a.sendFrame(&pb.TunnelFrame{
		Payload:       binary.AppendUvarint(nil, uint64(n)), // #nosec G115 -- n > 0
		MessageType:   WindowMessageType,
		TransactionId: txnID,
		Timestamps:    &pb.Timestamps{RequestAtAgent: time.Now().UnixMilli()},
		Routing:       routing,
	})
	if err != nil && a.ctx.Err() == nil {
		log.Printf("rpcclient: window update for transaction %s: %v", txnID, err)
	}
}

// handleWindow takes a window update for a call this agent makes or serves.
// One the call's credit cannot take (past the window, malformed) refuses
// that call; the connection's other calls go on.
func (a *Agent) handleWindow(msg *pb.TunnelFrame) {
	txnID := msg.GetTransactionId()
	n, size := binary.Uvarint(msg.GetPayload())
	bad := size <= 0 || size != len(msg.GetPayload()) || n > ResponseWindow
	if val, ok := a.pending.Load(txnID); ok {
		if bad || a.callCredit.Grant(txnID, int(n)) != nil { // #nosec G115 -- n <= ResponseWindow
			val.(*clientStream).refuse(errPastWindow)
		}
		return
	}
	if val, ok := a.incoming.Load(txnID); ok {
		if bad || a.serveCredit.Grant(txnID, int(n)) != nil { // #nosec G115 -- n <= ResponseWindow
			a.refuseCall(val.(*serverStream), "its caller granted more than the call's window")
		}
	}
}

// errPastWindow ends a call whose peer broke its credit.
var errPastWindow = status.Error(codes.ResourceExhausted, "rpcclient: the peer sent past the call's window")

// newServerStream makes the stream of a call this agent serves, its credit
// open until the call's context ends.
func (a *Agent) newServerStream(msg *pb.TunnelFrame, e2ee *a2aE2EEState, early []byte) *serverStream {
	ssCtx, ssCancel := context.WithCancel(a.ctx)
	txnID := msg.GetTransactionId()
	a.serveCredit.Open(txnID)
	context.AfterFunc(ssCtx, func() { a.serveCredit.Forget(txnID) })
	return &serverStream{
		agent:         a,
		txnID:         txnID,
		sourceAgentID: msg.GetRouting().GetAgentId(),
		sourceSession: msg.GetRouting().GetSourceSession(),
		ctx:           ssCtx,
		cancel:        ssCancel,
		requestCh:     make(chan *pb.TunnelFrame, RequestWindow+1), // + the request's end
		e2ee:          e2ee,
		early:         early,
	}
}
