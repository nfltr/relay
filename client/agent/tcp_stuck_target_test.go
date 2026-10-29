// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc/metadata"
)

// fakeRelayStream is a ConnectTCP stream whose relay side the test plays:
// in carries the relay's frames, every frame the agent sends is recorded.
type fakeRelayStream struct {
	in   chan *pb.TCPData
	stop chan struct{} // closed: Recv ends the stream
	md   metadata.MD

	mu     sync.Mutex
	closed map[string]bool // sessions the agent closed
	grants int            // window frames the agent sent
}

func (s *fakeRelayStream) Recv() (*pb.TCPData, error) {
	select {
	case f := <-s.in:
		return f, nil
	case <-s.stop:
		return nil, io.EOF
	}
}

// feed sends the relay's frames until the stream is stopped.
func (s *fakeRelayStream) feed(f *pb.TCPData) {
	select {
	case s.in <- f:
	case <-s.stop:
	}
}

func (s *fakeRelayStream) Send(f *pb.TCPData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case f.GetClose():
		s.closed[f.GetSessionId()] = true
	case f.GetSessionId() == dataplane.WindowSID:
		s.grants++
	}
	return nil
}

func (s *fakeRelayStream) Header() (metadata.MD, error) { return s.md, nil }

func (s *fakeRelayStream) wasClosed(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed[id]
}

// stuckTarget accepts connections and never reads them.
func stuckTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return ln.Addr().String()
}

// sinkTarget accepts one connection and reports once it read n bytes.
func sinkTarget(t *testing.T, n int) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close() //nolint:errcheck
		if _, err := io.CopyN(io.Discard, c, int64(n)); err == nil {
			close(got)
		}
	}()
	return ln.Addr().String(), got
}

// TestTCPTunnelStuckTargetDoesNotHoldTheReceiveLoop guards the agent's
// side of the stuck-client rule: a target
// that stops reading must not stop the stream's receive loop, which serves
// every session. With per-session credit (a relay that announced its
// window) the relay sends the stuck session at most the agent's window and
// the loop never waits; against a relay without credit the loop waits on
// the stuck session only for the stall bound, then resets it.
func TestTCPTunnelStuckTargetDoesNotHoldTheReceiveLoop(t *testing.T) {
	defer func(d time.Duration) { tcpSessionStall = d }(tcpSessionStall)
	tcpSessionStall = 300 * time.Millisecond
	for _, credit := range []bool{true, false} {
		t.Run("credit="+strconv.FormatBool(credit), func(t *testing.T) {
			st := &fakeRelayStream{in: make(chan *pb.TCPData), stop: make(chan struct{}), closed: map[string]bool{}}
			stuckBytes := 32 << 20 // past the gRPC queue and the target's socket buffers
			if credit {
				st.md = metadata.Pairs(dataplane.CreditHeader, strconv.Itoa(tcpDataWindow))
				stuckBytes = tcpDataWindow // all the agent's window allows
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- serveTCPStream(ctx, st, sessionTargets{}, nil, nil, slog.New(slog.DiscardHandler), nil, nil)
			}()
			defer func() { cancel(); close(st.stop); <-done }()
			sink, got := sinkTarget(t, 1<<20)
			stuck := stuckTarget(t)
			go func() {
				st.feed(&pb.TCPData{SessionId: "stuck", TargetAddr: stuck, Open: true})
				chunk := make([]byte, 64<<10)
				for sent := 0; sent < stuckBytes; sent += len(chunk) {
					st.feed(&pb.TCPData{SessionId: "stuck", Data: chunk})
				}
				st.feed(&pb.TCPData{SessionId: "other", TargetAddr: sink, Open: true})
				for range 16 {
					st.feed(&pb.TCPData{SessionId: "other", Data: chunk})
				}
			}()
			select {
			case <-got:
			case <-time.After(10 * time.Second):
				t.Fatal("another session got nothing beside a stuck target: the receive loop waits on it")
			}
			if st.wasClosed("stuck") == credit {
				t.Fatalf("stuck session closed: %v; want reset only without credit", st.wasClosed("stuck"))
			}
		})
	}
}

// TestTCPTunnelCreditRefusesARelayPastTheWindow: a relay that sends a
// session more than the agent's window ends the stream.
func TestTCPTunnelCreditRefusesARelayPastTheWindow(t *testing.T) {
	st := &fakeRelayStream{in: make(chan *pb.TCPData, 4), stop: make(chan struct{}), closed: map[string]bool{},
		md: metadata.Pairs(dataplane.CreditHeader, strconv.Itoa(tcpDataWindow))}
	st.in <- &pb.TCPData{SessionId: "s", TargetAddr: stuckTarget(t), Open: true}
	st.in <- &pb.TCPData{SessionId: "s", Data: make([]byte, tcpDataWindow)}
	st.in <- &pb.TCPData{SessionId: "s", Data: []byte("x")}
	err := serveTCPStream(context.Background(), st, sessionTargets{}, nil, nil, slog.New(slog.DiscardHandler), nil, nil)
	if err == nil {
		t.Fatal("a relay past the window kept its stream")
	}
}

// TestTCPTunnelStreamLossResetsTargets: a session whose stream ends under
// it (the relay or the path to it lost: no close, no half close from the
// relay) resets its target, never ends it cleanly: the target must not
// take the client's bytes it got for the whole stream. Before the fix the
// stream's end closed the target's connection with a FIN.
func TestTCPTunnelStreamLossResetsTargets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	end := make(chan error, 1)
	got := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			end <- err
			return
		}
		defer c.Close() //nolint:errcheck
		buf := make([]byte, 1)
		if _, err := io.ReadFull(c, buf); err != nil {
			end <- err
			return
		}
		close(got)
		_, err = io.Copy(io.Discard, c)
		end <- err // nil: a clean end
	}()
	st := &fakeRelayStream{in: make(chan *pb.TCPData), stop: make(chan struct{}), closed: map[string]bool{}}
	done := make(chan error, 1)
	go func() {
		done <- serveTCPStream(context.Background(), st, sessionTargets{}, nil, nil, slog.New(slog.DiscardHandler), nil, nil)
	}()
	st.feed(&pb.TCPData{SessionId: "s", TargetAddr: ln.Addr().String(), Open: true})
	st.feed(&pb.TCPData{SessionId: "s", Data: []byte("part of an upload")})
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the target got nothing")
	}
	close(st.stop) // the stream ends under the session
	<-done
	select {
	case err := <-end:
		if err == nil {
			t.Fatal("the target read a clean end after the stream ended under its session")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the target's connection did not end with the stream")
	}
}
