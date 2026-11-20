// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package nf1

import (
	"net"

	"github.com/nfltr/relay/client/capaddr"
	"testing"
)

// endConn records the session end calls an AnswerConn passes on.
type endConn struct {
	net.Conn
	calls []string
}

func (e *endConn) CloseWriteSyncReceived(received func()) error {
	e.calls = append(e.calls, "CloseWriteSyncReceived")
	received()
	return nil
}

func (e *endConn) CloseWrite() error {
	e.calls = append(e.calls, "CloseWrite")
	return nil
}

func (e *endConn) Reset() error {
	e.calls = append(e.calls, "Reset")
	return nil
}

// An AnswerConn passes its session's end on: tlsend finds a link
// session's half close with its ENDACK wait (CloseWriteSyncReceived) and
// its Reset through it. Hidden behind the embedded net.Conn, a relayed
// early dial's Close sent no FIN and its Reset was a clean close (lane
// PIPERESET; nfnet TestNF1EarlySessionResetIsAReset).
func TestAnswerConnPassesTheSessionsEnd(t *testing.T) {
	e := &endConn{}
	a := any(EarlyAnswer(e, capaddr.Address{}, false, nil))
	s, ok := a.(interface {
		CloseWrite() error
		CloseWriteSyncReceived(func()) error
		Reset() error
	})
	if !ok {
		t.Fatal("AnswerConn hides its session's CloseWrite, CloseWriteSyncReceived and Reset")
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := false
	if err := s.CloseWriteSyncReceived(func() { got = true }); err != nil || !got {
		t.Fatalf("CloseWriteSyncReceived: %v, received %v", err, got)
	}
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if len(e.calls) != 3 {
		t.Fatalf("passed on %v, want all three", e.calls)
	}
}
