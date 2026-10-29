// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
)

const testWindow = 4 * MaxChunk

// The link's frame format (github.com/nfltr/link doc.go), for raw frames.
const (
	typeData   = 0
	typeMsg    = 1
	typeWindow = 2
	maxData    = 1 << 20
	maxFrame   = 1 + 255 + maxData
	minWindow  = link.MinWindow
	maxWindow  = link.MaxWindow
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

// TestDataFrameIsRaw pins the data frame's encoding: header, session id,
// payload as sent, no protobuf.
func TestDataFrameIsRaw(t *testing.T) {
	var buf bytes.Buffer
	c := recordingV2(t, &buf)
	if err := c.Send(&pb.TCPData{SessionId: "12", Data: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	_ = c.Flush()
	want := []byte{0, 0, 0, 6, typeData, 2, '1', '2', 'a', 'b', 'c'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("got % x, want % x", buf.Bytes(), want)
	}
}

func TestRecvRejectsMalformedFrames(t *testing.T) {
	frame := func(n uint32, typ byte, body ...byte) []byte {
		b := binary.BigEndian.AppendUint32(nil, n)
		return append(append(b, typ), body...)
	}
	for name, raw := range map[string][]byte{
		"too large":        frame(maxFrame+1, typeData),
		"unknown type":     frame(1, 9, 0),
		"sid past body":    frame(2, typeData, 5, 'a'),
		"empty body":       frame(0, typeData),
		"empty data":       frame(1, typeData, 2),
		"bad protobuf":     frame(2, typeMsg, 0xff, 0xff),
		"truncated body":   frame(10, typeData, 1, 'a'),
		"short window":     frame(3, typeWindow, 0, 0, 1),
		"window sid wrong": frame(6, typeWindow, 2, 'a', 0, 0, 0, 1),
	} {
		t.Run(name, func(t *testing.T) {
			c := scripted(t, bytes.NewReader(raw), io.Discard)
			if _, err := c.Recv(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestCreditReturnedDataIsAcceptedAgain: once this side acknowledges
// consumed data, the peer may send that much more without ErrCredit.
func TestCreditReturnedDataIsAcceptedAgain(t *testing.T) {
	var wire bytes.Buffer
	peer := recordingV2(t, &wire)
	for range 3 {
		if err := peer.Send(&pb.TCPData{SessionId: "s", Data: make([]byte, testWindow/2)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := peer.Flush(); err != nil {
		t.Fatal(err)
	}
	c := scripted(t, &wire, io.Discard)
	c.Credit().Open("s")
	for i := range 3 {
		if _, err := c.Recv(); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if i == 1 {
			c.Credit().Consumed("s", testWindow/2) // returns half a window
		}
	}
}

// TestMessageDataIsCharged: data a message frame carries (a close with its
// last bytes) counts against the session's window, as data frames do.
func TestMessageDataIsCharged(t *testing.T) {
	var wire bytes.Buffer
	peer := recordingV2(t, &wire)
	for _, f := range []*pb.TCPData{
		{SessionId: "s", Data: make([]byte, testWindow-1)},
		{SessionId: "s", Data: []byte("ab"), Close: true},
	} {
		if err := peer.Send(f); err != nil {
			t.Fatal(err)
		}
	}
	_ = peer.Flush()
	c := scripted(t, &wire, io.Discard)
	c.Credit().Open("s")
	if _, err := c.Recv(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Recv(); !errors.Is(err, ErrCredit) {
		t.Fatalf("a close carrying data past the window: %v, want ErrCredit", err)
	}
}
