// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/nfltr/relay/client/rpcclient"
)

// SignalType identifies the type of a signaling message exchanged during P2P
// session negotiation.
type SignalType string

const (
	// SignalOffer is sent by the initiating peer.
	SignalOffer SignalType = "offer"
	// SignalAnswer is sent by the responding peer.
	SignalAnswer SignalType = "answer"

	// p2pMsgType is the rpcclient message-type sentinel that identifies P2P
	// signaling frames on the AgentTunnel stream.
	p2pMsgType = "p2p.v1"
)

// Meta describes the payload to be transferred in a P2P session.
type Meta struct {
	// Op is the operation, for example "send-file".
	Op string `json:"op"`
}

// SignalMsg is the JSON envelope exchanged between peers during signaling.
// Both offer and answer are transmitted as the payload of an rpcclient stream
// message with message_type "p2p.v1".
type SignalMsg struct {
	Type SignalType `json:"type"`
	// Session is a UUID that uniquely identifies this P2P session.
	Session string `json:"session"`
	// Key is the sender's ephemeral X25519 public key (hex; offer and answer).
	Key string `json:"key,omitempty"`
	// Candidates is the list of "host:port" addresses that the peer will
	// accept connections on.  Both local IPs and the STUN-discovered external
	// address are included.
	Candidates []string `json:"candidates"`
	// Meta describes the intended transfer.
	Meta *Meta `json:"meta,omitempty"`
}

// SendOffer transmits an offer over the provided ClientStream.
func SendOffer(stream rpcclient.ClientStream, msg *SignalMsg) error {
	msg.Type = SignalOffer
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("p2p: marshal offer: %w", err)
	}
	return stream.Send(b)
}

// RecvSignal reads a single SignalMsg from a ClientStream.
func RecvSignal(stream rpcclient.ClientStream) (*SignalMsg, error) {
	resp, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("p2p: recv signal: %w", err)
	}
	var msg SignalMsg
	if err := json.Unmarshal(resp.Data, &msg); err != nil {
		return nil, fmt.Errorf("p2p: unmarshal signal: %w", err)
	}
	return &msg, nil
}

// RecvSignalServer reads a single SignalMsg from a ServerStream.
func RecvSignalServer(stream rpcclient.ServerStream) (*SignalMsg, error) {
	data, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("p2p: recv signal: %w", err)
	}
	var msg SignalMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("p2p: unmarshal signal: %w", err)
	}
	return &msg, nil
}

// SendAnswer transmits an answer over the provided ServerStream.
func SendAnswer(stream rpcclient.ServerStream, msg *SignalMsg) error {
	msg.Type = SignalAnswer
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("p2p: marshal answer: %w", err)
	}
	return stream.Send(b)
}

// OpenSignalStream opens a bidirectional p2p.v1 signal stream from the local
// agent to targetAgentID.
func OpenSignalStream(ctx context.Context, agent *rpcclient.Agent, targetAgentID string) (rpcclient.ClientStream, error) {
	return agent.NewStream(ctx, targetAgentID, rpcclient.WithMessageType(p2pMsgType))
}
