// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package jsconn is the browser extension's transport for nf1 sessions
// (nfltr docs/decisions/browser-peer-2026-11-16.md, lane BP4): a WebSocket
// to wss://R/nf1/v1 or an RTCDataChannel as a net.Conn (conn_js.go), and
// the classes of the errors a session ends with. The classes are the
// CLI's exits for the same answers: the relay's WebSocket close codes
// (relay-core frontend/connect nf1ws.go) map onto client/nf1's errors.
package jsconn

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
)

// The relay path's close codes (the decision's BP2 wire).
const (
	CloseNormal    = 1000 // a clean end
	CloseIdle      = 1001 // no byte either way for nf1.websocket_idle
	CloseNoStatus  = 1005 // a close frame without a code
	CloseAbnormal  = 1006 // the connection went with no close frame (a relay restart)
	CloseUnsupport = 1003 // a text message
	CloseReset     = 1011 // a reset after the open
	CloseTryLater  = 1013 // no route now (draining, no answer in time)
	CloseNotServed = 4003 // unknown, offline or disabled address
	CloseRefused   = 4004 // a cap, or another reason named in the close reason
	CloseBalance   = 4009 // the serving account's balance
)

var (
	// ErrReset: the session was reset after it opened (close 1011).
	ErrReset = errors.New("nf1: the session was reset")
	// ErrIdle: the relay closed a session idle both ways (close 1001).
	ErrIdle = errors.New("nf1: the session was idle too long")
	// ErrProtocol: the transport broke the relay path's wire (a text
	// message, close 1003).
	ErrProtocol = errors.New("nf1: the relay path's wire was broken")
)

// CloseError is a transport the peer closed: its close code (0 for a data
// channel, which has none) and reason. It unwraps to its class.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	return fmt.Sprintf("%v (close %d %s)", e.Unwrap(), e.Code, e.Reason)
}

// Unwrap is the close code's class: client/nf1's errors for the relay's
// refusals, io.EOF for a clean end.
func (e *CloseError) Unwrap() error {
	switch e.Code {
	case CloseNormal, CloseNoStatus, 0:
		return io.EOF
	case CloseIdle:
		return ErrIdle
	case CloseReset:
		return ErrReset
	case CloseUnsupport:
		return ErrProtocol
	case CloseNotServed:
		return nf1.ErrNotServed
	case CloseRefused:
		return nf1.ErrRefused
	case CloseBalance:
		return nf1.ErrBalance
	default: // 1013, 1006 and any other: the relay was not reached or went
		return nf1.ErrUnreachable
	}
}

// Classes, each with the CLI's exit code for the same answer (0: no exit
// of its own).
var classes = []struct {
	err  error
	name string
	exit int
}{
	{nf1.ErrNotServed, "not_served", 3},
	{nf1.ErrRefused, "refused", 4},
	{nf1.ErrUnreachable, "unreachable", 5},
	{nf1.ErrBalance, "balance", 9},
	{capaddr.ErrPin, "pin", 7},
	{capaddr.ErrRendezvous, "pin", 7},
	{capaddr.ErrTLS, "pin", 7},
	{capaddr.ErrProof, "proof", 10},
	{nf1.ErrKind, "kind", 0},
	{nf1.ErrAnswer, "answer", 0},
	{ErrReset, "reset", 0},
	{ErrIdle, "idle", 0},
	{ErrProtocol, "protocol", 0},
	{os.ErrDeadlineExceeded, "timeout", 5},
	{io.EOF, "closed", 0},
	{io.ErrUnexpectedEOF, "closed", 0},
}

// verdicts are the handshake's own findings about the server: they name
// the failure even when the relay closed the transport after it.
var verdicts = []error{capaddr.ErrPin, capaddr.ErrRendezvous, capaddr.ErrTLS, capaddr.ErrProof, nf1.ErrKind, nf1.ErrAnswer}

// Classify names err's class and the CLI's exit for it. closed is the
// transport's close, if the peer closed it: a handshake that failed
// because the relay closed the WebSocket (a refusal) is the close code's
// class, not the read error the handshake saw, unless the handshake
// found the server is not the address's (a verdict).
func Classify(err error, closed *CloseError) (name string, exit int) {
	if closed != nil && !slices.ContainsFunc(verdicts, func(v error) bool { return errors.Is(err, v) }) {
		err = closed
	}
	for _, c := range classes {
		if errors.Is(err, c.err) {
			return c.name, c.exit
		}
	}
	return "error", 0
}
