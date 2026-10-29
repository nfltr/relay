// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"github.com/nfltr/relay/client/rpcclient"
	"google.golang.org/protobuf/proto"
)

// laggingTunnel is an agent's tunnel to the relay whose sent frames reach the
// peer after a delay, and are lost if the agent exits first: frames a gRPC
// transport had queued die with the process.
type laggingTunnel struct {
	*mockSignalTunnel
	mu      sync.Mutex
	queue   []*pb.TunnelFrame
	exited  bool
	peerIn  chan<- *pb.TunnelFrame
	onExit  func()
	latency time.Duration
}

func (l *laggingTunnel) Send(msg *pb.TunnelFrame) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.exited {
		return io.ErrClosedPipe
	}
	l.queue = append(l.queue, proto.Clone(msg).(*pb.TunnelFrame)) // a transport serializes
	if len(l.queue) == 1 {
		go l.deliver()
	}
	return nil
}

func (l *laggingTunnel) deliver() {
	for {
		time.Sleep(l.latency)
		l.mu.Lock()
		if l.exited || len(l.queue) == 0 {
			l.mu.Unlock()
			return
		}
		msg := l.queue[0]
		l.queue = l.queue[1:]
		more := len(l.queue) > 0
		l.mu.Unlock()
		l.peerIn <- msg
		if !more {
			return
		}
	}
}

// copyingTunnel copies each frame on Send, as a gRPC transport serializes it:
// the caller may reuse its buffer as soon as Send returns.
type copyingTunnel struct{ *mockSignalTunnel }

// allow:wrapper — the copy is the point: it models the transport.
func (c copyingTunnel) Send(msg *pb.TunnelFrame) error {
	return c.mockSignalTunnel.Send(proto.Clone(msg).(*pb.TunnelFrame))
}

// exit drops what is still queued and disconnects the peer, as the relay
// does when an agent goes away ("target agent disconnected").
func (l *laggingTunnel) exit() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.exited {
		l.exited, l.queue = true, nil
		l.onExit()
	}
}

// TestRelayFallbackTransferSucceedsWhenTheReceiverExitsAtOnce (R3-G10): over
// the relay, a receiver that exits as soon as ReceiveFile returns must not
// take its ack with it. The file used to arrive intact while the sender
// failed with "waiting for ack … target agent disconnected" and exit 1.
func TestRelayFallbackTransferSucceedsWhenTheReceiverExitsAtOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sourceTunnel := newMockSignalTunnel(ctx)
	targetTunnel := newMockSignalTunnel(ctx)
	var closeSource sync.Once
	target := &laggingTunnel{
		mockSignalTunnel: targetTunnel,
		peerIn:           sourceTunnel.recvCh,
		latency:          20 * time.Millisecond,
		onExit:           func() { closeSource.Do(func() { close(sourceTunnel.recvCh) }) },
	}
	go func() { // source → target: the relay forwards at once
		for {
			select {
			case msg := <-sourceTunnel.sendCh:
				targetTunnel.recvCh <- msg
			case <-ctx.Done():
				return
			}
		}
	}()

	sender := rpcclient.NewAgent("sender", copyingTunnel{sourceTunnel})
	defer sender.Close() //nolint:errcheck
	receiver := rpcclient.NewAgent("receiver", target)
	defer receiver.Close() //nolint:errcheck

	outDir := t.TempDir()
	received := make(chan error, 1)
	receiver.Handle(func(stream rpcclient.ServerStream) error {
		conn := NewServerRelayConn(stream)
		_, err := ReceiveFile(conn, outDir, nil)
		target.exit() // the receiver's process ends right away
		received <- err
		return err
	})

	src := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(src, make([]byte, 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	stream, err := sender.NewStream(ctx, "receiver")
	if err != nil {
		t.Fatal(err)
	}
	conn := NewClientRelayConn(stream)
	sendErr := SendFile(conn, src, nil)
	_ = conn.Close()
	if err := <-received; err != nil {
		t.Fatalf("ReceiveFile: %v", err)
	}
	if sendErr != nil {
		t.Fatalf("SendFile over the relay: %v; the receiver saved the file, the sender must succeed", sendErr)
	}
}
