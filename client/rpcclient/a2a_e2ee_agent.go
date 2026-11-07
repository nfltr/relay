// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// Agent-side A2A E2EE policy: the handshake responder, the downgrade
// refusal and the pairing key.

import (
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
	return !relayOriginated || !a.a2aRelayRequests.Load() || a.keyring() != nil
}

// keyring is this agent's A2A E2EE keys, or nil (unkeyed).
func (a *Agent) keyring() A2AE2EEKeyring {
	if k := a.a2aKeyring.Load(); k != nil {
		return *k
	}
	return nil
}

func (a *Agent) handleE2EEInit(msg *pb.TunnelFrame) string {
	if !a.a2aE2EEInbound.Load() {
		a.sendA2AControlError(msg.GetTransactionId(), codes.FailedPrecondition,
			"target agent does not support A2A E2EE; retry with --e2ee=false or upgrade the target")
		return "Refuse"
	}

	a.handlerMu.RLock()
	h := a.handler
	a.handlerMu.RUnlock()
	if h == nil {
		a.sendA2AControlError(msg.GetTransactionId(), codes.Unimplemented,
			"target agent has no A2A handler registered")
		return "Refuse"
	}

	// A call this agent already serves is never started a second time.
	if _, serving := a.incoming.Load(msg.GetTransactionId()); serving {
		log.Printf("rpcclient: dropped an A2A E2EE init for txn %s, a call this agent already serves", msg.GetTransactionId())
		return "" // a second start of a served call: dropped, not traced
	}
	state, ack, err := newServerA2AE2EEState(msg.GetTransactionId(), a.agentID, msg.GetPayload(), a.keyring(), rand.Reader)
	if err != nil {
		code := codes.InvalidArgument
		if errors.Is(err, errA2AE2EEPairing) {
			code = codes.FailedPrecondition
		}
		a.sendA2AControlError(msg.GetTransactionId(), code, err.Error())
		return "Refuse"
	}
	if state.retry != nil {
		if err := a.sessions.retry(state.retry, state.caller, state.kid); err != nil {
			a.sendA2AControlError(msg.GetTransactionId(), codes.Aborted, err.Error())
			return "Refuse"
		}
	}

	if state.established != nil {
		a.sessions.putIn(state.established)
	}
	return a.startE2EECall(msg, state, a2aE2EEAckMessageType, ack)
}

// handleE2EEResume starts a call on a session (a2a_e2ee_session.go): one
// this agent keeps, its tag, a call number not taken, a key that still
// holds; else it answers unknown (not the call's end: the relay keeps the
// call's route for the caller's handshake).
func (a *Agent) handleE2EEResume(msg *pb.TunnelFrame) string {
	if !a.a2aE2EEInbound.Load() {
		a.sendA2AControlError(msg.GetTransactionId(), codes.FailedPrecondition,
			"target agent does not support A2A E2EE; retry with --e2ee=false or upgrade the target")
		return "Refuse"
	}
	a.handlerMu.RLock()
	h := a.handler
	a.handlerMu.RUnlock()
	if h == nil {
		a.sendA2AControlError(msg.GetTransactionId(), codes.Unimplemented,
			"target agent has no A2A handler registered")
		return "Refuse"
	}
	if _, serving := a.incoming.Load(msg.GetTransactionId()); serving {
		log.Printf("rpcclient: dropped an A2A E2EE resume for txn %s, a call this agent already serves", msg.GetTransactionId())
		return ""
	}
	kr := a.keyring()
	s, c, err := a.sessions.resume(msg.GetTransactionId(), msg.GetPayload(), kr)
	if err != nil {
		if sendErr := a.sendFrame(&pb.TunnelFrame{
			MessageType:   a2aE2EEUnknownMessageType,
			TransactionId: msg.GetTransactionId(),
			Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
			Routing:       &pb.RoutingInfo{AgentId: a.agentID},
		}); sendErr != nil {
			log.Printf("rpcclient: failed to answer an unknown A2A E2EE session for txn %s: %v", msg.GetTransactionId(), sendErr)
		}
		return "Refuse"
	}
	return a.startE2EECall(msg, newResumedServerA2AE2EEState(msg.GetTransactionId(), s, c, kr), a2aE2EEResumedMessageType, nil)
}

// startE2EECall serves an E2EE call whose start this agent took: its
// answer (the ack, or resumed), then the handler.
func (a *Agent) startE2EECall(msg *pb.TunnelFrame, state *a2aE2EEState, answerType string, answer []byte) string {
	a.handlerMu.RLock()
	h := a.handler
	a.handlerMu.RUnlock()
	ss := a.newServerStream(msg, state)
	a.incoming.Store(ss.txnID, ss)

	if err := a.sendFrame(&pb.TunnelFrame{
		Payload:       answer,
		MessageType:   answerType,
		TransactionId: ss.txnID,
		Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
		Routing:       &pb.RoutingInfo{AgentId: a.agentID},
	}); err != nil {
		ss.end()
		a.incoming.Delete(ss.txnID)
		log.Printf("rpcclient: failed to send A2A E2EE %s for txn %s: %v", answerType, ss.txnID, err)
		return "Refuse"
	}

	a.wg.Add(1)
	go a.handleCall(ss, h)
	return "Start"
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
