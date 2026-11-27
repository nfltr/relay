// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package dataplane holds the wire pieces of a TCP tunnel's sessions
// besides the gRPC messages: the agent link's hello and open headers
// (agentlink.go; a github.com/nfltr/link link of wire version 2 on the
// relay's gRPC port, told apart from HTTP/2 by AgentLinkMagic), the
// /connect upgrade's Mux (upgrade.go, mux.go), the in-band answers
// (answer.go), and the control frames of a ConnectTCP gRPC stream: where
// both sides announce their window in CreditHeader (the agent in its
// request metadata, the relay in its response header) they keep
// per-session credit themselves, window updates travelling as control
// frames (WindowFrame). Agent data connections (x-nfltr-tcp-data, a
// pb.TCPData adapter over a link connection) were retired in lane
// LINKV013 (nfltr docs/decisions/link-data-connections-retired-2026-11-20.md).
package dataplane

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
)

// CreditHeader carries a side's per-session window on a ConnectTCP gRPC
// stream: the agent's in its request metadata, the relay's in its
// response header. With both, the stream's sessions run on credit.
const CreditHeader = "x-nfltr-tcp-credit" // #nosec G101 -- a header name, not a credential

// EndAckHeader, "1" in an agent's ConnectTCP request metadata and echoed
// in the relay's response header, says both sides of the gRPC stream
// acknowledge a session's half close (EndAckFrame): a side ends a session
// cleanly only once its own half close was acked, and resets its app when
// the stream ends first (relay-core spec/README.md finding 2). Without it
// on both sides no ack is sent or awaited.
const EndAckHeader = "x-nfltr-tcp-end-ack"

// EndAckSID is the session id of the control frame that acknowledges a
// session's half close on a gRPC stream (EndAckFrame).
const EndAckSID = "_endack"

// EndAckFrame acknowledges sid's half close: every byte the peer sent
// before it was received (the stream is FIFO).
func EndAckFrame(sid string) *pb.TCPData {
	return &pb.TCPData{SessionId: EndAckSID, Data: []byte(sid)}
}

// EndDoneHeader, "1" in an agent's ConnectTCP request metadata and echoed
// in the relay's response header (each with EndAckHeader), says both sides
// report a session's half close delivered (EndDoneFrame): a closer's
// wait for its end (the relay's in-process conn's CloseWriteSync, the
// agent's accepted conn's Close) returns nil only once the peer's app
// took every byte and the end. An ack (EndAckFrame) is a receipt only:
// holds and a session's clean end stay on it (relay-core spec/AgentLink.tla
// DoneTruth, mutants done-on-receipt and hold-on-done).
const EndDoneHeader = "x-nfltr-tcp-end-done"

// EndDoneSID is the session id of the control frame that reports a
// session's half close delivered (EndDoneFrame).
const EndDoneSID = "_enddone"

// EndDoneFrame reports sid's half close delivered: the sender's onward
// conn took every byte before it and the end (a link session's
// CloseWriteSync returned nil; a target's CloseWrite did).
func EndDoneFrame(sid string) *pb.TCPData {
	return &pb.TCPData{SessionId: EndDoneSID, Data: []byte(sid)}
}

// HTTPSessionTarget is the target of a session that carries HTTP/1.1 to the
// agent's own HTTP server: the relay's reverse proxy writes requests into
// it and the agent serves them with net/http, in place of HTTP requests as
// ConnectHTTP messages (client generation 3).
const HTTPSessionTarget = "nfltr:http"

// HTTPSessionsHeader, "1" in an agent's ConnectTCP request metadata, says
// its TCP streams serve sessions to HTTPSessionTarget; the relay then sends
// the agent's HTTP requests there.
const HTTPSessionsHeader = "x-nfltr-http-sessions"

// WindowSID is the session id of the control frame that carries a window
// update on a gRPC stream (WindowFrame).
const WindowSID = "_window"

// WindowFrame is the control frame that grants n bytes of sid's credit on
// a gRPC stream.
func WindowFrame(sid string, n int) *pb.TCPData {
	return &pb.TCPData{SessionId: WindowSID, Data: link.AppendWindow(nil, sid, n)}
}

// ParseWindowFrame reads a WindowFrame's grant.
func ParseWindowFrame(f *pb.TCPData) (string, int, error) { return link.ParseWindow(f.GetData()) }

// ParseCreditHeader parses a CreditHeader value as a window.
func ParseCreditHeader(s string) (int, error) { return parseWindow(s) }

// bindToken is the agent's credential on its agent link (BindToken).
type bindToken string

func (t bindToken) Hello(context.Context, tls.ConnectionState) (byte, []byte, error) {
	return link.MethodToken, []byte(t), nil
}

func (bindToken) Verify(context.Context, tls.ConnectionState, byte, []byte) (link.Identity, error) {
	return link.Identity{}, errors.New("dataplane: a bind token is the agent's, not verified here")
}

// The link's constants, as this package named them.
const (
	Magic    = link.Magic
	MaxChunk = link.MaxChunk
)

var ErrRefused = link.ErrRefused
