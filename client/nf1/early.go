// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nf1

import (
	"net"

	"github.com/nfltr/relay/client/capaddr"
)

// AnswerConn is a session opened at the address's relay whose first Read
// takes the answers to the open: the relay's (Answered) and the
// rendezvous answer (ReadAnswer, CheckKind). ClientTLS runs on it as soon
// as the open is sent: its ClientHello depends on no answer and carries no
// secret, so it travels with the open, and the answers are checked before
// TLS reads the server's first byte (the client still acts on nothing the
// server sent before the pin and the record are checked). This saves the
// open's round trip through the relay and the agent (nfltr
// docs/decisions/nf1-ttfb-2026-11-15.md); the wire and the server are
// unchanged. Guard: nfnet TestNF1ClientHelloGoesWithOpen.
type AnswerConn struct {
	net.Conn
	addr     capaddr.Address
	datagram bool
	answered func() error
	read     bool
	hints    []byte
	err      error
}

// EarlyAnswer is conn as an AnswerConn; answered waits for the relay's
// answer to the open (nil once it came), its error returned as is.
func EarlyAnswer(conn net.Conn, addr capaddr.Address, datagram bool, answered func() error) *AnswerConn {
	return &AnswerConn{Conn: conn, addr: addr, datagram: datagram, answered: answered}
}

// Read takes the answers at the first call; their failure is every
// call's error (Err).
func (a *AnswerConn) Read(p []byte) (int, error) {
	if err := a.Err(); err != nil {
		return 0, err
	}
	return a.Conn.Read(p)
}

// Err takes the answers if no Read did yet and returns their failure (nil
// once they were taken): after a failed handshake it says more than the
// handshake's error (a refused open fails the ClientHello's write before
// TLS reads), so callers check it first. Not concurrent with Read.
func (a *AnswerConn) Err() error {
	if !a.read {
		a.read = true
		if a.err = a.answered(); a.err == nil {
			a.hints, a.err = ReadAnswer(a.Conn, a.addr)
			if a.err == nil {
				a.err = CheckKind(a.hints, a.datagram)
			}
			if a.err == nil && Anonymous(a.hints) { // an early session is never framed for direct paths
				a.err = ErrDirectRequired
			}
		}
	}
	return a.err
}

// Hints are the rendezvous answer's hints once it was taken.
func (a *AnswerConn) Hints() []byte { return a.hints }

// sessionEnd is the end of the session under an AnswerConn (a link
// session's): its half close with the far end's acknowledgement, and its
// reset.
type sessionEnd interface {
	CloseWriteSyncReceived(received func()) error
	Reset() error
}

// CloseWriteSyncReceived is the session's (link.Session's): tlsend's
// CloseWriteSync half-closes it after the close_notify and waits for the
// far end's ENDACK. On a conn without one it only runs received. Hidden
// behind net.Conn, a relayed early dial's Close sent no FIN: its whole
// close then reached the listener before its end was acknowledged, a reset
// there (lane PIPERESET; link WIRE.md 13, ENDACKTRUTH).
func (a *AnswerConn) CloseWriteSyncReceived(received func()) error {
	if s, ok := a.Conn.(sessionEnd); ok { // a link session: its FIN, then the far end's ENDACK
		return s.CloseWriteSyncReceived(received)
	}
	received()
	return nil
}

// Reset is the session's reset (tlsend's Reset: the peer reads a reset,
// never a clean end); on a conn without one, its Close.
func (a *AnswerConn) Reset() error {
	if s, ok := a.Conn.(sessionEnd); ok { // a link session: the peer reads a reset
		return s.Reset()
	}
	return a.Conn.Close()
}
