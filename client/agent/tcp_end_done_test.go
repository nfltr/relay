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

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/proto/wire/agentservices"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc/metadata"
)

// endDoneSession serves a stream whose relay announced the end
// acknowledgement and the delivery report, opens session "s" to a queued
// service and returns the stream and the accepted conn.
func endDoneSession(t *testing.T) (*ackRelayStream, net.Conn) {
	t.Helper()
	q := NewSessionQueue(0)
	tab, err := NewServiceTable([]Service{{Name: "svc", Kind: agentservices.TCP, Queue: q}})
	if err != nil {
		t.Fatal(err)
	}
	st := &ackRelayStream{in: make(chan *pb.TCPData), out: make(chan *pb.TCPData, 64), stop: make(chan struct{}),
		md: metadata.Pairs(dataplane.CreditHeader, strconv.Itoa(tcpDataWindow), dataplane.EndAckHeader, "1", dataplane.EndDoneHeader, "1")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveTCPStream(ctx, st, sessionTargets{services: tab}, nil, nil, slog.New(slog.DiscardHandler), &tcpStreamGrowth{}, nil)
	}()
	t.Cleanup(func() {
		cancel()
		stopStream(st)
		<-done
	})
	st.in <- &pb.TCPData{SessionId: "s", Open: true, TargetAddr: "svc"}
	c, err := q.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.(*QueueConn).Reset() })
	return st, c
}

func stopStream(st *ackRelayStream) {
	select {
	case <-st.stop:
	default:
		close(st.stop)
	}
}

// closeAfterTail writes "tail" on c, closes it on its own goroutine and
// returns Close's result once the agent sent the tail, the half close and
// the relay acked it.
func closeAfterTail(t *testing.T, st *ackRelayStream, c net.Conn) <-chan error {
	t.Helper()
	if _, err := c.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	st.next(t, "half close", func(f *pb.TCPData) bool { return f.GetSessionId() == "s" && f.GetClose() && f.GetHalf() })
	st.in <- dataplane.EndAckFrame("s") // a receipt: the relay's app has read nothing
	select {
	case err := <-closed:
		t.Fatalf("Close returned %v at the relay's receipt; want it to wait for the delivery report", err)
	case <-time.After(300 * time.Millisecond):
	}
	return closed
}

// An accepted conn's Close on a gRPC stream returns once the relay
// reported its end delivered (dataplane.EndDoneFrame), never at the
// relay's receipt (lane ENDGRPC finding 4: it returned at once;
// relay-core spec/AgentLink.tla DoneTruth, mutant done-on-receipt).
func TestQueueConnCloseOnGRPCWaitsForEndDone(t *testing.T) {
	st, c := endDoneSession(t)
	closed := closeAfterTail(t, st, c)
	st.in <- dataplane.EndDoneFrame("s")
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close after the delivery report: %v; want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return after the delivery report")
	}
}

// The stream ends after the relay's receipt and before its report: the
// end is not known delivered (link.ErrReset), never nil.
func TestQueueConnCloseOnGRPCStreamEndBeforeEndDone(t *testing.T) {
	st, c := endDoneSession(t)
	closed := closeAfterTail(t, st, c)
	stopStream(st)
	select {
	case err := <-closed:
		if !errors.Is(err, link.ErrReset) {
			t.Fatalf("Close after the stream's end: %v; want link.ErrReset", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return after the stream ended")
	}
}

// The relay's half close reaches the accepted conn (EOF after the bytes
// before it): the agent reports it delivered.
func TestTCPTunnelSendsEndDoneOnceTargetTookTheEnd(t *testing.T) {
	st, c := endDoneSession(t)
	st.in <- &pb.TCPData{SessionId: "s", Data: []byte("hi")}
	st.in <- &pb.TCPData{SessionId: "s", Close: true, Half: true}
	if b, err := io.ReadAll(c); err != nil || string(b) != "hi" {
		t.Fatalf("read %q, %v; want hi, then EOF", b, err)
	}
	st.next(t, "delivery report", func(f *pb.TCPData) bool {
		return f.GetSessionId() == dataplane.EndDoneSID && string(f.GetData()) == "s"
	})
}
