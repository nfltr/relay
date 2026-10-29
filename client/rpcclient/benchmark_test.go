// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
)

// ---------------------------------------------------------------------------
// Shared benchmark helpers
// ---------------------------------------------------------------------------

// benchStream is an optimised mock stream for benchmarks — direct channels,
// no real gRPC.
type benchStream struct {
	sendCh chan *pb.TunnelFrame
	recvCh chan *pb.TunnelFrame
	ctx    context.Context
}

func newBenchStream(ctx context.Context) *benchStream {
	return &benchStream{
		sendCh: make(chan *pb.TunnelFrame, 256),
		recvCh: make(chan *pb.TunnelFrame, 256),
		ctx:    ctx,
	}
}

func (s *benchStream) Send(msg *pb.TunnelFrame) error {
	select {
	case s.sendCh <- msg:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *benchStream) Recv() (*pb.TunnelFrame, error) {
	select {
	case msg, ok := <-s.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

// echoResponder sits on the send side of a benchStream and echoes back every
// request as a response with EOM, simulating an instant agent reply. It runs
// until ctx is cancelled.
func echoResponder(ctx context.Context, bs *benchStream) {
	for {
		select {
		case msg, ok := <-bs.sendCh:
			if !ok {
				return
			}
			txnID := msg.GetTransactionId()
			// Send data response.
			resp := &pb.TunnelFrame{
				Payload:       msg.GetPayload(),
				MessageType:   "a2a-response",
				TransactionId: txnID,
				Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
				Routing:       &pb.RoutingInfo{AgentId: "echo"},
			}
			select {
			case bs.recvCh <- resp:
			case <-ctx.Done():
				return
			}
			// Send status trailer with EOM.
			trailer := &pb.TunnelFrame{
				MessageType:   "a2a-status",
				TransactionId: txnID,
				Eom:           true,
				StatusCode:    int32(codes.OK),
			}
			select {
			case bs.recvCh <- trailer:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Agent.Invoke (unary round-trip)
// ---------------------------------------------------------------------------

func BenchmarkAgent_Invoke(b *testing.B) {
	ctx := b.Context()

	bs := newBenchStream(ctx)
	agent := NewAgent("bench-a", bs)
	defer agent.Close() //nolint:errcheck
	go echoResponder(ctx, bs)

	payload := []byte("benchmark-payload-round-trip")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := agent.Invoke(ctx, "bench-b", payload)
		if err != nil {
			b.Fatalf("Invoke: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Agent.Invoke with increasing payload sizes
// ---------------------------------------------------------------------------

func BenchmarkAgent_Invoke_PayloadSize(b *testing.B) {
	for _, size := range []int{64, 1024, 16384, 65536} {
		b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
			ctx := b.Context()

			bs := newBenchStream(ctx)
			agent := NewAgent("bench-a", bs)
			defer agent.Close() //nolint:errcheck
			go echoResponder(ctx, bs)

			payload := make([]byte, size)
			for j := range payload {
				payload[j] = byte(j % 256)
			}

			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				_, err := agent.Invoke(ctx, "bench-b", payload)
				if err != nil {
					b.Fatalf("Invoke: %v", err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Agent.NewStream (streaming send + recv)
// ---------------------------------------------------------------------------

func BenchmarkAgent_Stream(b *testing.B) {
	for _, msgs := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("msgs=%d", msgs), func(b *testing.B) {
			ctx := b.Context()

			bs := newBenchStream(ctx)
			agent := NewAgent("bench-a", bs)
			defer agent.Close() //nolint:errcheck

			// Streaming responder: reads all sends, echoes one response per stream.
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case msg, ok := <-bs.sendCh:
						if !ok {
							return
						}
						// Only reply when we see EOM.
						if msg.GetEom() {
							txnID := msg.GetTransactionId()
							resp := &pb.TunnelFrame{
								Payload:       []byte("resp"),
								MessageType:   "a2a-response",
								TransactionId: txnID,
								Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
								Routing:       &pb.RoutingInfo{AgentId: "echo"},
							}
							bs.recvCh <- resp
							// Status trailer.
							bs.recvCh <- &pb.TunnelFrame{
								MessageType:   "a2a-status",
								TransactionId: txnID,
								Eom:           true,
								StatusCode:    int32(codes.OK),
							}
						}
					}
				}
			}()

			chunk := []byte("stream-chunk-data")

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				stream, err := agent.NewStream(ctx, "bench-b")
				if err != nil {
					b.Fatalf("NewStream: %v", err)
				}
				for range msgs {
					if err := stream.Send(chunk); err != nil {
						b.Fatalf("Send: %v", err)
					}
				}
				if err := stream.CloseSend(); err != nil {
					b.Fatalf("CloseSend: %v", err)
				}
				_, err = stream.Recv()
				if err != nil {
					b.Fatalf("Recv: %v", err)
				}
				// Drain EOF.
				_, _ = stream.Recv()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Agent.Handle (incoming call dispatch)
// ---------------------------------------------------------------------------

func BenchmarkAgent_Handle(b *testing.B) {
	ctx := b.Context()

	bs := newBenchStream(ctx)
	agent := NewAgent("bench-handler", bs)
	defer agent.Close() //nolint:errcheck

	var handlerWg sync.WaitGroup

	agent.Handle(func(stream ServerStream) error {
		defer handlerWg.Done()
		data, err := stream.Recv()
		if err != nil {
			return err
		}
		return stream.Send(data)
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		txnID := fmt.Sprintf("bench-txn-%d", i)
		handlerWg.Add(1)

		// Inject an incoming call message.
		bs.recvCh <- &pb.TunnelFrame{
			Payload:       []byte("incoming"),
			MessageType:   "a2a-request",
			TransactionId: txnID,
			Timestamps:    &pb.Timestamps{RequestAtAgent: time.Now().UnixMilli()},
			Routing:       &pb.RoutingInfo{AgentId: "caller", TargetAgentId: "bench-handler"},
			Eom:           true,
		}

		handlerWg.Wait()
		// Drain the two sends from handler (response + status trailer).
		<-bs.sendCh
		<-bs.sendCh
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Concurrent Agent.Invoke (parallel callers)
// ---------------------------------------------------------------------------

func BenchmarkAgent_Invoke_Parallel(b *testing.B) {
	ctx := b.Context()

	bs := newBenchStream(ctx)
	agent := NewAgent("bench-a", bs)
	defer agent.Close() //nolint:errcheck
	go echoResponder(ctx, bs)

	payload := []byte("parallel-payload")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := agent.Invoke(ctx, "bench-b", payload)
			if err != nil {
				b.Errorf("Invoke: %v", err)
				return
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Benchmark: message building (sendMsg hot path)
// ---------------------------------------------------------------------------

func BenchmarkClientStream_SendMsg(b *testing.B) {
	ctx := b.Context()

	bs := newBenchStream(ctx)
	agent := NewAgent("bench-a", bs)
	defer agent.Close() //nolint:errcheck

	// Drain sends continuously.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-bs.sendCh:
			}
		}
	}()

	cs := &clientStream{
		agent:         agent,
		txnID:         "bench-sendmsg",
		targetAgentID: "target",
		sourceAgentID: "bench-a",
		msgType:       "a2a-request",
		responseCh:    make(chan *pb.TunnelFrame, 16),
		headerCh:      make(chan struct{}),
		ctx:           ctx,
	}

	data := []byte("sendmsg-benchmark-payload")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cs.sendMsg(data, false)
	}
}

// ---------------------------------------------------------------------------
// Benchmark: recvLoop message demux throughput
// ---------------------------------------------------------------------------

func BenchmarkRecvLoop_Demux(b *testing.B) {
	ctx := b.Context()

	bs := newBenchStream(ctx)
	agent := NewAgent("bench-demux", bs)
	defer agent.Close() //nolint:errcheck

	// Pre-register pending client streams with large buffers.
	const numStreams = 10
	streams := make([]*clientStream, numStreams)
	for i := range numStreams {
		cs := &clientStream{
			txnID:      fmt.Sprintf("demux-txn-%d", i),
			responseCh: make(chan *pb.TunnelFrame, 4096),
			headerCh:   make(chan struct{}),
			ctx:        ctx,
		}
		streams[i] = cs
		agent.pending.Store(cs.txnID, cs)
	}

	// Drain responses from all streams continuously.
	for _, cs := range streams {
		go func(ch chan *pb.TunnelFrame) {
			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-ch:
					if !ok {
						return
					}
				}
			}
		}(cs.responseCh)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		idx := i % numStreams
		bs.recvCh <- &pb.TunnelFrame{
			Payload:       []byte("demux-msg"),
			MessageType:   "a2a-response",
			TransactionId: streams[idx].txnID,
			Timestamps:    &pb.Timestamps{ResponseAtAgent: time.Now().UnixMilli()},
			Routing:       &pb.RoutingInfo{AgentId: "responder"},
		}
		// Wait for the response to be consumed.
		for len(streams[idx].responseCh) > 4000 {
			time.Sleep(time.Microsecond)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Full round-trip through handler (agent A → agent B, in-process)
// ---------------------------------------------------------------------------

func BenchmarkFullRoundTrip(b *testing.B) {
	ctx := b.Context()

	// Agent B — the handler agent.
	bsB := newBenchStream(ctx)
	agentB := NewAgent(testTargetAgentId, bsB)
	defer agentB.Close() //nolint:errcheck

	agentB.Handle(func(stream ServerStream) error {
		data, err := stream.Recv()
		if err != nil {
			return err
		}
		return stream.Send(data)
	})

	// Agent A — the caller agent.
	bsA := newBenchStream(ctx)
	agentA := NewAgent("agent-a", bsA)
	defer agentA.Close() //nolint:errcheck

	// Bridge: route messages between the two agents (simulating the server).
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-bsA.sendCh:
				if !ok {
					return
				}
				// If target_agent_id is set, route to B's recv.
				if msg.GetRouting().GetTargetAgentId() == testTargetAgentId {
					select {
					case bsB.recvCh <- msg:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-bsB.sendCh:
				if !ok {
					return
				}
				select {
				case bsA.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	payload := []byte("full-roundtrip-payload")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp, err := agentA.Invoke(ctx, testTargetAgentId, payload)
		if err != nil {
			b.Fatalf("Invoke: %v", err)
		}
		if string(resp) != string(payload) {
			b.Fatalf("expected echo, got %q", resp)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Full round-trip (parallel)
// ---------------------------------------------------------------------------

func BenchmarkFullRoundTrip_Parallel(b *testing.B) {
	ctx := b.Context()

	bsB := newBenchStream(ctx)
	agentB := NewAgent(testTargetAgentId, bsB)
	defer agentB.Close() //nolint:errcheck
	agentB.Handle(func(stream ServerStream) error {
		data, err := stream.Recv()
		if err != nil {
			return err
		}
		return stream.Send(data)
	})

	bsA := newBenchStream(ctx)
	agentA := NewAgent("agent-a", bsA)
	defer agentA.Close() //nolint:errcheck

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-bsA.sendCh:
				if !ok {
					return
				}
				if msg.GetRouting().GetTargetAgentId() == testTargetAgentId {
					select {
					case bsB.recvCh <- msg:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-bsB.sendCh:
				if !ok {
					return
				}
				select {
				case bsA.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	payload := []byte("parallel-roundtrip")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := agentA.Invoke(ctx, testTargetAgentId, payload)
			if err != nil {
				b.Errorf("Invoke: %v", err)
				return
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Benchmark: parseTarget (micro-benchmark for hot utility)
// ---------------------------------------------------------------------------

func BenchmarkParseTarget(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = parseTarget("relay:9090")
	}
}
