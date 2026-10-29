// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/nfltr/relay/client/rpcclient"
)

// SignalType identifies the type of a signaling message exchanged during P2P
// session negotiation.  The vocabulary mirrors WebRTC (offer / answer / hangup).
type SignalType string

const (
	// SignalOffer is sent by the initiating peer.  It carries connection
	// candidates and the initiator's end-to-end public key.
	SignalOffer SignalType = "offer"
	// SignalAnswer is sent by the responding peer.  It carries that peer's
	// connection candidates, public key and key confirmation.
	SignalAnswer SignalType = "answer"
	// SignalConfirm is the initiator's key confirmation, the message after
	// the answer (E2E.FinishOffer).
	SignalConfirm SignalType = "confirm"
	// SignalSelect is the dialing side's choice among the direct
	// connections that authenticated (Conn: its ConnID), sent after the
	// answer (AnnounceConn). A peer that predates it never sends it, and its
	// peer then keeps its own pick.
	SignalSelect SignalType = "select"
	// SignalHangup terminates signaling before a direct connection is formed.
	SignalHangup SignalType = "hangup"

	// SignalProto is the signaling protocol a CLI speaks, in every offer and
	// answer. From 2, after the offer/answer the relay stream is a RelayMux:
	// sequenced signaling frames from the first message (a call starts at
	// once; the direct TCP channel joins later), and file data on a WebRTC
	// data channel (OpenDataPath). From 3, every session is end-to-end
	// encrypted (E2E): the offer and answer carry X25519 public keys instead
	// of a session token, the initiator confirms the keys, and the signaling
	// frames and the data stream are sealed on every path. A peer below 3 is
	// refused, never served in the clear. An older peer omits it (0).
	SignalProto = 3

	// p2pMsgType is the rpcclient message-type sentinel that identifies P2P
	// signaling frames on the AgentTunnel stream.
	p2pMsgType = "p2p.v1"
)

// Note: SignalRelay is defined in relay.go.

// Meta describes the payload to be transferred in a P2P session.
type Meta struct {
	// Op is the operation: "send-file", "send-dir", "chat", or "call". The
	// file's name, size and SHA-256 travel inside the encrypted data stream.
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
	// Confirm is a key confirmation (answer and SignalConfirm).
	Confirm string `json:"confirm,omitempty"`
	// Candidates is the list of "host:port" addresses that the peer will
	// accept connections on.  Both local IPs and the STUN-discovered external
	// address are included.
	Candidates []string `json:"candidates"`
	// Meta describes the intended transfer (file, dir, or chat).
	Meta *Meta `json:"meta,omitempty"`
	// Error is set in a hangup message to describe the failure reason.
	Error string `json:"error,omitempty"`
	// Conn is the ConnID of the direct connection the dialing side keeps
	// (SignalSelect).
	Conn string `json:"conn,omitempty"`
	// Proto is the sender's SignalProto (0 from a CLI that predates it).
	Proto int `json:"proto,omitempty"`
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

// SendHangupServer sends a hangup message and closes the server stream.
func SendHangupServer(stream rpcclient.ServerStream, sessionID, reason string) {
	msg := &SignalMsg{Type: SignalHangup, Session: sessionID, Error: reason}
	b, _ := json.Marshal(msg)
	_ = stream.Send(b)
}

// OpenSignalStream opens a bidirectional p2p.v1 signal stream from the local
// agent to targetAgentID.
func OpenSignalStream(ctx context.Context, agent *rpcclient.Agent, targetAgentID string) (rpcclient.ClientStream, error) {
	return agent.NewStream(ctx, targetAgentID, rpcclient.WithMessageType(p2pMsgType))
}

// SendRelay sends a relay signal on a ClientStream, indicating that the
// initiator wants to fall back to server-relayed data transfer.
func SendRelay(stream rpcclient.ClientStream, sessionID string) error {
	msg := &SignalMsg{Type: SignalRelay, Session: sessionID}
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("p2p: marshal relay: %w", err)
	}
	return stream.Send(b)
}

// ErrPeerRelay is Connect's error, with AwaitConn, when the dialing side
// sent SignalRelay instead of a connection: the session continues on the
// server relay (NewServerRelayConn).
var ErrPeerRelay = errors.New("p2p: peer chose the server relay")

// errNoSelection: the peer sent another signal than SignalSelect.
var errNoSelection = errors.New("p2p: no connection selection")

// ConnectOption configures Connect.
type ConnectOption func(*connectConfig)

type connectConfig struct {
	announce func(connID string) error
	await    func() (connID string, err error)
}

// AnnounceConn makes Connect, on the dialing side, send the connection it
// keeps to the peer on the signaling stream (SignalSelect with Conn).
func AnnounceConn(stream rpcclient.ClientStream, sessionID string) ConnectOption {
	return func(c *connectConfig) {
		c.announce = func(id string) error {
			b, err := json.Marshal(&SignalMsg{Type: SignalSelect, Session: sessionID, Conn: id})
			if err != nil {
				return err
			}
			return stream.Send(b)
		}
	}
}

// AwaitConn makes Connect, on the other side, keep the connection the
// dialing side announced (AnnounceConn), read from the signaling stream.
// Another signal or the stream's end (a peer that predates SignalSelect)
// leaves Connect keeping its own pick; SignalRelay makes it return
// ErrPeerRelay.
func AwaitConn(stream rpcclient.ServerStream) ConnectOption {
	return func(c *connectConfig) {
		c.await = func() (string, error) {
			msg, err := RecvSignalServer(stream)
			switch {
			case err != nil:
				return "", err
			case msg.Type == SignalRelay:
				return "", ErrPeerRelay
			case msg.Type != SignalSelect || msg.Conn == "":
				return "", errNoSelection
			}
			return msg.Conn, nil
		}
	}
}
