// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/nfltr/link"

	"github.com/nfltr/relay/proto/pb"
)

const testWindow = 4 * MaxChunk

func TestWindowFrame(t *testing.T) {
	sid, n, err := ParseWindowFrame(WindowFrame("s7", 1<<20))
	if err != nil || sid != "s7" || n != 1<<20 {
		t.Fatalf("%q %d %v", sid, n, err)
	}
	if _, _, err := ParseWindowFrame(&pb.TCPData{SessionId: WindowSID, Data: []byte{9}}); err == nil {
		t.Fatal("malformed window frame parsed")
	}
}

const (
	minWindow = link.MinWindow
	maxWindow = link.MaxWindow
)

// bufConn is a net.Conn that reads r and writes w.
type bufConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

// Read: net.Conn over r. allow:wrapper
func (c bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// Write: net.Conn over w. allow:wrapper
func (c bufConn) Write(b []byte) (int, error) { return c.w.Write(b) }

// closingConn is a bufConn that a handshake and Close may use.
type closingConn struct{ bufConn }

// Close: no-op. allow:wrapper
func (closingConn) Close() error { return nil }

// SetDeadline: no-op. allow:wrapper
func (closingConn) SetDeadline(time.Time) error { return nil }

// boundReply is a listener's link reply that binds.
func boundReply() []byte {
	reply := []byte{0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	reply[6], reply[7] = byte(testWindow>>24), byte(testWindow>>16) // window, big endian
	reply[13] = 64                                                  // max sessions
	return reply
}
