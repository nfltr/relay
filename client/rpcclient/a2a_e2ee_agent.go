// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// Agent-side A2A E2EE policy: the handshake responder, the downgrade
// refusal and the pairing key.

import (
	"context"
	"crypto/rand"
	"errors"
	"log"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
)

// RelayAgentID is the relay's own agent: presence label updates go to it and
// the dashboard's calls to a user's agents come from it.
// Streams to it end at the relay.
const RelayAgentID = "nfltr-relay"

// fleetInvokeMessageType is the request the relay itself sends fleet targets.
const fleetInvokeMessageType = "fleet-invoke"

// refusesPlaintext reports whether a new plaintext request must be refused:
// this agent encrypts its own streams (E2EE on), and the request is not one
// the relay originates itself on an agent that accepts those. A pairing key
// declares the relay untrusted, so a keyed agent refuses relay-authored
// work too; without one the relay could run its own handshake anyway, so
// refusing its plaintext would add nothing.
func (a *Agent) refusesPlaintext(msg *pb.TunnelFrame) bool {
	if !a.a2aE2EEOutbound.Load() {
		return false
	}
	relayOriginated := msg.GetRouting().GetAgentId() == RelayAgentID || msg.GetMessageType() == fleetInvokeMessageType
	return !relayOriginated || !a.a2aRelayRequests.Load() || a.pairingKey() != nil
}

func (a *Agent) pairingKey() []byte {
	if k := a.a2aPairingKey.Load(); k != nil {
		return *k
	}
	return nil
}

func (a *Agent) handleE2EEInit(msg *pb.TunnelFrame) {
	if !a.a2aE2EEInbound.Load() {
		a.sendA2AControlError(msg.GetTransactionId(), codes.FailedPrecondition,
			"target agent does not support A2A E2EE; retry with --e2ee=false or upgrade the target")
		return
	}

	a.handlerMu.RLock()
	h := a.handler
	a.handlerMu.RUnlock()
	if h == nil {
		a.sendA2AControlError(msg.GetTransactionId(), codes.Unimplemented,
			"target agent has no A2A handler registered")
		return
	}

	// A call this agent already serves (its 0-RTT first flight was taken)
	// is never started a second time.
	if _, serving := a.incoming.Load(msg.GetTransactionId()); serving {
		log.Printf("rpcclient: dropped an A2A E2EE init for txn %s, a call this agent already serves", msg.GetTransactionId())
		return
	}
	state, responderPub, err := newServerA2AE2EEState(msg.GetTransactionId(), msg.GetPayload(), a.pairingKey())
	if err != nil {
		code := codes.InvalidArgument
		if errors.Is(err, errA2AE2EEPairing) {
			code = codes.FailedPrecondition
		}
		a.sendA2AControlError(msg.GetTransactionId(), code, err.Error())
		return
	}

	ssCtx, ssCancel := context.WithCancel(a.ctx)
	ss := &serverStream{
		agent:         a,
		txnID:         msg.GetTransactionId(),
		sourceAgentID: msg.GetRouting().GetAgentId(),
		ctx:           ssCtx,
		cancel:        ssCancel,
		requestCh:     make(chan *pb.TunnelFrame, 16),
		e2ee:          state,
	}
	a.incoming.Store(ss.txnID, ss)

	if err := a.sendFrame(&pb.TunnelFrame{
		Payload:       responderPub,
		MessageType:   a2aE2EEAckMessageType,
		TransactionId: ss.txnID,
		Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
		Routing:       &pb.RoutingInfo{AgentId: a.agentID},
	}); err != nil {
		ssCancel()
		a.incoming.Delete(ss.txnID)
		log.Printf("rpcclient: failed to send A2A E2EE ack for txn %s: %v", ss.txnID, err)
		return
	}

	a.wg.Add(1)
	go a.handleCall(ss, h)
}

// e2eeStatic is this agent's static key: the process's, unless replaced.
func (a *Agent) e2eeStatic() *a2aE2EEStatic {
	if st := a.a2aStatic.Load(); st != nil {
		return st
	}
	st, _ := processA2AE2EEStatic()
	return st
}

// handleE2EEInit0RTT takes a 0-RTT first flight (a2a_e2ee_0rtt.go): it
// answers message 2 at once and starts the handler with the request, or
// refuses it with a2a-e2ee-retry and the caller runs the interactive
// handshake on the same call.
func (a *Agent) handleE2EEInit0RTT(msg *pb.TunnelFrame) {
	txnID := msg.GetTransactionId()
	if !a.a2aE2EEInbound.Load() {
		a.sendA2AControlError(txnID, codes.FailedPrecondition,
			"target agent does not support A2A E2EE; retry with --e2ee=false or upgrade the target")
		return
	}
	a.handlerMu.RLock()
	h := a.handler
	a.handlerMu.RUnlock()
	if h == nil {
		a.sendA2AControlError(txnID, codes.Unimplemented, "target agent has no A2A handler registered")
		return
	}
	if _, serving := a.incoming.Load(txnID); serving {
		log.Printf("rpcclient: dropped an A2A E2EE first flight for txn %s, a call this agent already serves", txnID)
		return
	}
	pairing := a.pairingKey()
	var accepted a2aE2EEAccepted
	var e []byte
	refusal := refuseBad
	if st := a.e2eeStatic(); st != nil {
		accepted, e, refusal = st.accept(pairing, txnID, msg.GetPayload(), time.Now(), rand.Reader)
	}
	if refusal != 0 {
		if err := a.sendFrame(&pb.TunnelFrame{
			Payload:       retryPayload(pairing, a.agentID, txnID, e, refusal),
			MessageType:   a2aE2EERetryMessageType,
			TransactionId: txnID,
			Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
			Routing:       &pb.RoutingInfo{AgentId: a.agentID},
		}); err != nil {
			log.Printf("rpcclient: failed to send A2A E2EE retry for txn %s: %v", txnID, err)
		}
		return
	}
	ssCtx, ssCancel := context.WithCancel(a.ctx)
	ss := &serverStream{
		agent:         a,
		txnID:         txnID,
		sourceAgentID: msg.GetRouting().GetAgentId(),
		ctx:           ssCtx,
		cancel:        ssCancel,
		requestCh:     make(chan *pb.TunnelFrame, 16),
		e2ee:          accepted.state,
		early:         accepted.request,
	}
	a.incoming.Store(txnID, ss)
	if err := a.sendFrame(&pb.TunnelFrame{
		Payload:       accepted.ack,
		MessageType:   a2aE2EEAckMessageType,
		TransactionId: txnID,
		Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
		Routing:       &pb.RoutingInfo{AgentId: a.agentID},
	}); err != nil {
		ssCancel()
		a.incoming.Delete(txnID)
		log.Printf("rpcclient: failed to send A2A E2EE ack for txn %s: %v", txnID, err)
		return
	}
	a.wg.Add(1)
	go a.handleCall(ss, h)
}

func (a *Agent) sendA2AControlError(txnID string, code codes.Code, detail string) {
	if err := a.sendFrame(&pb.TunnelFrame{
		MessageType:   "error",
		TransactionId: txnID,
		Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
		Routing:       &pb.RoutingInfo{AgentId: a.agentID},
		Eom:           true,
		StatusCode:    int32(code),
		StatusDetail:  detail,
	}); err != nil {
		log.Printf("rpcclient: failed to send control error for txn %s: %v", txnID, err)
	}
}
