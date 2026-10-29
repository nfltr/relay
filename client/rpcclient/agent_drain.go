// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"strings"
	"time"
	"uuid"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The drain handshake:
// an agent leaving for good tells the relay before it closes its stream. The
// relay acknowledges on the same stream, after every new call it already
// forwarded; from then on it answers a new call to the agent with
// AgentDrainingDetail (codes.Unavailable) without delivering it, also after
// the agent left. Frames of calls already delivered still flow.
const (
	AgentDrainMessageType    = "agent.drain"
	AgentDrainAckMessageType = "agent.drain.ack"
	AgentDrainingDetail      = "target agent is draining: it takes no new call and is leaving"
)

// IsAgentDraining reports a call the relay refused because its target is
// draining or left after draining: the target never received it.
func IsAgentDraining(err error) bool {
	s, ok := status.FromError(err)
	return ok && s.Code() == codes.Unavailable && strings.HasPrefix(s.Message(), AgentDrainingDetail)
}

// Drain asks the relay to route no new call to this agent, waits for its
// acknowledgement, then for every call already delivered to be answered, so
// none is lost when the agent closes. ctx bounds it: a relay that predates
// the handshake never acknowledges.
func (a *Agent) Drain(ctx context.Context) error {
	txnID := uuid.New().String()
	ack := make(chan struct{})
	a.drainAcks.Store(txnID, ack)
	defer a.drainAcks.Delete(txnID)
	if err := a.sendFrame(&pb.TunnelFrame{
		MessageType: AgentDrainMessageType, TransactionId: txnID, Eom: true,
		Routing:    &pb.RoutingInfo{AgentId: a.agentID},
		Timestamps: &pb.Timestamps{RequestAtAgent: time.Now().UnixMilli()},
	}); err != nil {
		return err
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for acked := false; ; {
		select {
		case <-ack:
			acked, ack = true, nil
		case <-tick.C:
		case <-a.done:
			return a.Err()
		case <-ctx.Done():
			return ctx.Err()
		}
		if acked && !a.hasIncomingCalls() {
			return nil
		}
	}
}

func (a *Agent) hasIncomingCalls() bool {
	busy := false
	a.incoming.Range(func(any, any) bool { busy = true; return false })
	return busy
}

// handleDrainAck closes Drain's wait for the relay's acknowledgement.
func (a *Agent) handleDrainAck(txnID string) {
	if ack, ok := a.drainAcks.LoadAndDelete(txnID); ok {
		close(ack.(chan struct{}))
	}
}
