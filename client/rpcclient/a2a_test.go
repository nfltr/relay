// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/nfltr/relay/proto/pb"
)

const testTargetAgentId = "agent-b"

// ---------------------------------------------------------------------------
// mockStream — simulates the AgentTunnel for testing
// ---------------------------------------------------------------------------

type mockStream struct {
	sendCh chan *pb.TunnelFrame
	recvCh chan *pb.TunnelFrame
	ctx    context.Context
}

type slowSendStream struct {
	sentCh    chan *pb.TunnelFrame
	recvCh    chan *pb.TunnelFrame
	ctx       context.Context
	dataDelay time.Duration
}

type gatedSendStream struct {
	sentCh      chan *pb.TunnelFrame
	recvCh      chan *pb.TunnelFrame
	dataStarted chan struct{}
	releaseData chan struct{}
	startOnce   sync.Once
	ctx         context.Context
}

type failingSendStream struct {
	ctx     context.Context
	sendErr error
	recvCh  chan *pb.TunnelFrame
}

func newMockStream(ctx context.Context) *mockStream {
	return &mockStream{
		sendCh: make(chan *pb.TunnelFrame, 32),
		recvCh: make(chan *pb.TunnelFrame, 32),
		ctx:    ctx,
	}
}

func newSlowSendStream(ctx context.Context, dataDelay time.Duration) *slowSendStream {
	return &slowSendStream{
		sentCh:    make(chan *pb.TunnelFrame, 256),
		recvCh:    make(chan *pb.TunnelFrame, 1),
		ctx:       ctx,
		dataDelay: dataDelay,
	}
}

func newGatedSendStream(ctx context.Context) *gatedSendStream {
	return &gatedSendStream{
		sentCh:      make(chan *pb.TunnelFrame, 8),
		recvCh:      make(chan *pb.TunnelFrame, 1),
		dataStarted: make(chan struct{}),
		releaseData: make(chan struct{}),
		ctx:         ctx,
	}
}

func newFailingSendStream(ctx context.Context, sendErr error) *failingSendStream {
	return &failingSendStream{
		ctx:     ctx,
		sendErr: sendErr,
		recvCh:  make(chan *pb.TunnelFrame),
	}
}

func (m *mockStream) Send(msg *pb.TunnelFrame) error {
	select {
	case m.sendCh <- msg:
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}

func (m *mockStream) Recv() (*pb.TunnelFrame, error) {
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

func (m *slowSendStream) Send(msg *pb.TunnelFrame) error {
	if msg.GetTransactionId() != "" || len(msg.GetPayload()) > 0 || msg.GetEom() {
		timer := time.NewTimer(m.dataDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-m.ctx.Done():
			return m.ctx.Err()
		}
	}
	select {
	case m.sentCh <- msg:
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}

func (m *slowSendStream) Recv() (*pb.TunnelFrame, error) {
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

func (m *gatedSendStream) Send(msg *pb.TunnelFrame) error {
	if msg.GetTransactionId() != "" || len(msg.GetPayload()) > 0 || msg.GetEom() {
		m.startOnce.Do(func() { close(m.dataStarted) })
		select {
		case <-m.releaseData:
		case <-m.ctx.Done():
			return m.ctx.Err()
		}
	}
	select {
	case m.sentCh <- msg:
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}

func (m *gatedSendStream) Recv() (*pb.TunnelFrame, error) {
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

func (m *failingSendStream) Send(*pb.TunnelFrame) error {
	return m.sendErr
}

func (m *failingSendStream) Recv() (*pb.TunnelFrame, error) {
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

// ---------------------------------------------------------------------------
// Unary: Invoke
// ---------------------------------------------------------------------------
