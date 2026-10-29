// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/client/rpcclient"
)

type mockSignalTunnel struct {
	sendCh chan *pb.TunnelFrame
	recvCh chan *pb.TunnelFrame
	ctx    context.Context
}

func newMockSignalTunnel(ctx context.Context) *mockSignalTunnel {
	return &mockSignalTunnel{
		sendCh: make(chan *pb.TunnelFrame, 32),
		recvCh: make(chan *pb.TunnelFrame, 32),
		ctx:    ctx,
	}
}

func (m *mockSignalTunnel) Send(msg *pb.TunnelFrame) error {
	select {
	case m.sendCh <- msg:
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}

func (m *mockSignalTunnel) Recv() (*pb.TunnelFrame, error) {
	select {
	case msg, ok := <-m.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-m.ctx.Done():
		return nil, m.ctx.Err()
	}
}

func TestSignalStream_OfferAnswerBeforeCloseSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sourceTunnel := newMockSignalTunnel(ctx)
	targetTunnel := newMockSignalTunnel(ctx)

	source := rpcclient.NewAgent("agent-a", sourceTunnel)
	defer source.Close() //nolint:errcheck

	target := rpcclient.NewAgent("agent-b", targetTunnel)
	defer target.Close() //nolint:errcheck

	var (
		bridgeMu       sync.Mutex
		sourceToTarget []*pb.TunnelFrame
		targetToSource []*pb.TunnelFrame
	)

	bridge := func(src <-chan *pb.TunnelFrame, dst chan<- *pb.TunnelFrame, sink *[]*pb.TunnelFrame) {
		for {
			select {
			case msg, ok := <-src:
				if !ok {
					return
				}
				bridgeMu.Lock()
				*sink = append(*sink, msg)
				bridgeMu.Unlock()
				select {
				case dst <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}

	go bridge(sourceTunnel.sendCh, targetTunnel.recvCh, &sourceToTarget)
	go bridge(targetTunnel.sendCh, sourceTunnel.recvCh, &targetToSource)

	handlerDone := make(chan error, 1)
	target.Handle(func(stream rpcclient.ServerStream) error {
		offer, err := RecvSignalServer(stream)
		if err != nil {
			handlerDone <- err
			return err
		}
		if offer.Type != SignalOffer {
			err = io.ErrUnexpectedEOF
			handlerDone <- err
			return err
		}
		if err := SendAnswer(stream, &SignalMsg{
			Session:    offer.Session,
			Candidates: []string{"10.0.0.2:4242"},
		}); err != nil {
			handlerDone <- err
			return err
		}
		relay, err := RecvSignalServer(stream)
		if err != nil {
			handlerDone <- err
			return err
		}
		if relay.Type != SignalRelay {
			err = io.ErrUnexpectedEOF
			handlerDone <- err
			return err
		}
		handlerDone <- nil
		return nil
	})

	stream, err := OpenSignalStream(ctx, source, "agent-b")
	if err != nil {
		t.Fatal(err)
	}

	offer := &SignalMsg{
		Session:    "session-1",
		Key:        "deadbeef",
		Candidates: []string{"10.0.0.1:3131"},
		Meta:       &Meta{Op: "send-file"},
	}
	if err := SendOffer(stream, offer); err != nil {
		t.Fatalf("SendOffer: %v", err)
	}

	answer, err := RecvSignal(stream)
	if err != nil {
		t.Fatalf("RecvSignal before CloseSend: %v", err)
	}
	if answer.Type != SignalAnswer {
		t.Fatalf("expected answer, got %q", answer.Type)
	}
	if answer.Session != offer.Session {
		t.Fatalf("expected session %q, got %q", offer.Session, answer.Session)
	}

	if err := SendRelay(stream, offer.Session); err != nil {
		t.Fatalf("SendRelay: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("expected io.EOF after status trailer, got %v", err)
	}

	select {
	case err := <-handlerDone:
		if err != nil {
			t.Fatalf("handler returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("handler did not complete")
	}

	// The handler answers (and the status trailer ends Recv) without waiting
	// for the CloseSend frame: wait for the bridge to have carried it.
	for {
		bridgeMu.Lock()
		n := len(sourceToTarget)
		bridgeMu.Unlock()
		if n >= 3 || ctx.Err() != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	if len(sourceToTarget) < 3 {
		t.Fatalf("expected at least 3 source->target frames, got %d", len(sourceToTarget))
	}
	if sourceToTarget[0].GetMessageType() != p2pMsgType {
		t.Fatalf("expected first request message type %q, got %q", p2pMsgType, sourceToTarget[0].GetMessageType())
	}
	if sourceToTarget[2].GetEom() != true {
		t.Fatal("expected final CloseSend marker with EOM=true")
	}
	if len(targetToSource) == 0 || targetToSource[0].GetMessageType() != "a2a-response" {
		t.Fatal("expected answer response from target before status trailer")
	}
}
