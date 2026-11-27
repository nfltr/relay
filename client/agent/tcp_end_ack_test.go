// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc/metadata"
)

// ackRelayStream is a ConnectTCP stream whose relay side the test plays:
// in carries the relay's frames, out every frame the agent sends.
type ackRelayStream struct {
	in   chan *pb.TCPData
	out  chan *pb.TCPData
	stop chan struct{} // closed: Recv ends the stream
	md   metadata.MD
}

func (s *ackRelayStream) Recv() (*pb.TCPData, error) {
	select {
	case f := <-s.in:
		return f, nil
	case <-s.stop:
		return nil, io.EOF
	}
}

func (s *ackRelayStream) Send(f *pb.TCPData) error {
	s.out <- f
	return nil
}

func (s *ackRelayStream) Header() (metadata.MD, error) { return s.md, nil }

// next is the agent's next frame that match takes; it fails the test after
// a bound against a hang.
func (s *ackRelayStream) next(t *testing.T, what string, match func(*pb.TCPData) bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case f := <-s.out:
			if match(f) {
				return
			}
		case <-deadline:
			t.Fatalf("the agent sent no %s", what)
		}
	}
}

// endAckSession serves a stream whose relay announced (endAck) or did not
// announce the end acknowledgement, opens session "s" to a target that
// writes "tail" and half-closes, and returns the target's end of the
// connection once the agent sent the tail and its half close.
func endAckSession(t *testing.T, endAck bool) (*ackRelayStream, net.Conn) {
	t.Helper()
	st := &ackRelayStream{in: make(chan *pb.TCPData), out: make(chan *pb.TCPData, 64), stop: make(chan struct{}),
		md: metadata.Pairs(dataplane.CreditHeader, strconv.Itoa(tcpDataWindow))}
	if endAck {
		st.md.Set(dataplane.EndAckHeader, "1")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveTCPStream(ctx, st, sessionTargets{}, nil, nil, slog.New(slog.DiscardHandler), nil, nil)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-st.stop:
		default:
			close(st.stop)
		}
		<-done
	})
	st.in <- &pb.TCPData{SessionId: "s", TargetAddr: ln.Addr().String(), Open: true}
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	st.next(t, "half close", func(f *pb.TCPData) bool { return f.GetSessionId() == "s" && f.GetClose() && f.GetHalf() })
	return st, c
}

// readEnd is how the target's read side ends within d: nil while it has
// not (a deadline), else the read's error.
func readEnd(c net.Conn, d time.Duration) error {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil
	}
	if err == nil {
		return io.EOF
	}
	return err
}

// The target half-closed first and the relay's half close came: the target
// reads EOF only once the relay acked its half close, so its tail cannot
// be lost behind a clean end (relay-core spec/README.md finding 2).
func TestTCPTunnelEndAckHoldsTargetEOFUntilAcked(t *testing.T) {
	st, c := endAckSession(t, true)
	st.in <- &pb.TCPData{SessionId: "s", Close: true, Half: true}
	st.next(t, "ack of the relay's half close", func(f *pb.TCPData) bool {
		return f.GetSessionId() == dataplane.EndAckSID && string(f.GetData()) == "s"
	})
	if err := readEnd(c, 200*time.Millisecond); err != nil {
		t.Fatalf("target's read ended before its half close was acked: %v", err)
	}
	st.in <- dataplane.EndAckFrame("s")
	if err := readEnd(c, 10*time.Second); err != io.EOF {
		t.Fatalf("target's read after the ack: %v, want EOF", err)
	}
}

// The stream ends while the target's half close waits for its ack: the
// target is reset, never ended cleanly.
func TestTCPTunnelEndAckStreamLossResetsTarget(t *testing.T) {
	st, c := endAckSession(t, true)
	st.in <- &pb.TCPData{SessionId: "s", Close: true, Half: true}
	st.next(t, "ack of the relay's half close", func(f *pb.TCPData) bool { return f.GetSessionId() == dataplane.EndAckSID })
	close(st.stop)
	if err := readEnd(c, 10*time.Second); err == nil || err == io.EOF {
		t.Fatalf("target's read after the stream's loss: %v, want a reset", err)
	}
}

// A relay that does not announce the end acknowledgement gets none and
// the session ends at both half closes, as before.
func TestTCPTunnelEndAckOldRelay(t *testing.T) {
	st, c := endAckSession(t, false)
	st.in <- &pb.TCPData{SessionId: "s", Close: true, Half: true}
	if err := readEnd(c, 10*time.Second); err != io.EOF {
		t.Fatalf("target's read: %v, want EOF", err)
	}
	for {
		select {
		case f := <-st.out:
			if f.GetSessionId() == dataplane.EndAckSID {
				t.Fatal("the agent acked on a stream without the end acknowledgement")
			}
		default:
			return
		}
	}
}
