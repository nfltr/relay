// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFullRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Two mock streams: one for source agent, one for target agent.
	msSource := newMockStream(ctx)
	msTarget := newMockStream(ctx)

	source := NewAgent("agent-a", msSource)
	defer source.Close() //nolint:errcheck

	target := NewAgent(testTargetAgentId, msTarget)
	defer target.Close() //nolint:errcheck

	// Target handler: echo each message back with prefix.
	target.Handle(func(stream ServerStream) error {
		stream.SetHeader(MD{"x-echo": "true"})
		for {
			data, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if err := stream.Send([]byte("echo:" + string(data))); err != nil {
				return err
			}
		}
		return nil
	})

	// Bridge: forward source sends → target recvs, target sends → source recvs.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msSource.sendCh:
				if !ok {
					return
				}
				select {
				case msTarget.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msTarget.sendCh:
				if !ok {
					return
				}
				select {
				case msSource.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Source: send 2 messages, receive echoes.
	stream, err := source.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send([]byte("hello"))
	_ = stream.Send([]byte("world"))
	_ = stream.CloseSend()

	var resps []string
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		resps = append(resps, string(resp.Data))
	}

	if len(resps) != 2 {
		t.Fatalf("expected 2 responses, got %d: %v", len(resps), resps)
	}
	if resps[0] != "echo:hello" || resps[1] != "echo:world" {
		t.Fatalf("unexpected responses: %v", resps)
	}

	// Verify initial metadata.
	hdr, err := stream.Header()
	if err != nil {
		t.Fatal(err)
	}
	if hdr["x-echo"] != "true" {
		t.Fatalf("expected x-echo=true, got %v", hdr)
	}
}

func TestFullRoundTrip_E2EE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msSource := newMockStream(ctx)
	msTarget := newMockStream(ctx)

	source := NewAgent("agent-a", msSource)
	source.EnableA2AE2EE()
	defer source.Close() //nolint:errcheck

	target := NewAgent(testTargetAgentId, msTarget)
	target.EnableA2AE2EE()
	defer target.Close() //nolint:errcheck

	target.Handle(func(stream ServerStream) error {
		stream.SetHeader(MD{"x-echo": "true"})
		for {
			data, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if err := stream.Send([]byte("echo:" + string(data))); err != nil {
				return err
			}
		}
		return nil
	})

	var mu sync.Mutex
	var sourceToTarget []*pb.TunnelFrame
	var targetToSource []*pb.TunnelFrame

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msSource.sendCh:
				if !ok {
					return
				}
				mu.Lock()
				sourceToTarget = append(sourceToTarget, msg)
				mu.Unlock()
				select {
				case msTarget.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msTarget.sendCh:
				if !ok {
					return
				}
				mu.Lock()
				targetToSource = append(targetToSource, msg)
				mu.Unlock()
				select {
				case msSource.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	stream, err := source.NewStream(ctx, testTargetAgentId)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}

	var resps []string
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		resps = append(resps, string(resp.Data))
	}

	if len(resps) != 2 {
		t.Fatalf("expected 2 responses, got %d: %v", len(resps), resps)
	}
	if resps[0] != "echo:hello" || resps[1] != "echo:world" {
		t.Fatalf("unexpected responses: %v", resps)
	}

	hdr, err := stream.Header()
	if err != nil {
		t.Fatal(err)
	}
	if hdr["x-echo"] != "true" {
		t.Fatalf("expected x-echo=true, got %v", hdr)
	}
	if hdr[a2aE2EEHeaderKey] != "true" {
		t.Fatalf("expected %s=true, got %v", a2aE2EEHeaderKey, hdr)
	}

	mu.Lock()
	defer mu.Unlock()
	var sawInit bool
	var sawEncryptedRequest bool
	for _, msg := range sourceToTarget {
		switch msg.GetMessageType() {
		case a2aE2EEInitMessageType:
			sawInit = true
		case "a2a-request":
			if string(msg.GetPayload()) == "hello" || string(msg.GetPayload()) == "world" {
				t.Fatalf("request payload leaked plaintext over transport: %q", msg.GetPayload())
			}
			sawEncryptedRequest = true
		}
	}
	if !sawInit {
		t.Fatal("expected A2A E2EE handshake init frame")
	}
	if !sawEncryptedRequest {
		t.Fatal("expected encrypted A2A request frames")
	}

	var sawEncryptedResponse bool
	for _, msg := range targetToSource {
		if msg.GetMessageType() != "a2a-response" {
			continue
		}
		if string(msg.GetPayload()) == "echo:hello" || string(msg.GetPayload()) == "echo:world" {
			t.Fatalf("response payload leaked plaintext over transport: %q", msg.GetPayload())
		}
		sawEncryptedResponse = true
	}
	if !sawEncryptedResponse {
		t.Fatal("expected encrypted A2A response frames")
	}
}

func TestAgentInboundOnlyE2EEAcceptsEncryptedCallsWithoutEncryptingOutbound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msSource := newMockStream(ctx)
	msTarget := newMockStream(ctx)

	source := NewAgent("encrypted-worker", msSource)
	source.EnableA2AE2EE()
	defer source.Close() //nolint:errcheck

	target := NewAgent("relay-orchestrator", msTarget, WithAgentInboundA2AE2EE())
	defer target.Close() //nolint:errcheck

	target.Handle(func(stream ServerStream) error {
		data, err := stream.Recv()
		if err != nil {
			return err
		}
		return stream.Send(append([]byte("ack:"), data...))
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msSource.sendCh:
				if !ok {
					return
				}
				select {
				case msTarget.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msTarget.sendCh:
				if !ok {
					return
				}
				select {
				case msSource.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	response, err := source.Invoke(ctx, "relay-orchestrator", []byte("resume-task"))
	if err != nil {
		t.Fatalf("encrypted inbound Invoke() error = %v", err)
	}
	if got, want := string(response), "ack:resume-task"; got != want {
		t.Fatalf("encrypted inbound response = %q, want %q", got, want)
	}

	outbound, err := target.NewStream(ctx, "plaintext-worker")
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	client, ok := outbound.(*clientStream)
	if !ok {
		t.Fatalf("NewStream() type = %T, want *clientStream", outbound)
	}
	if client.e2ee != nil {
		t.Fatal("inbound-only E2EE unexpectedly enabled encryption for an outbound stream")
	}
}

func TestInvoke_E2EEUnsupportedTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msSource := newMockStream(ctx)
	msTarget := newMockStream(ctx)

	source := NewAgent("agent-a", msSource)
	source.EnableA2AE2EE()
	defer source.Close() //nolint:errcheck

	target := NewAgent(testTargetAgentId, msTarget)
	defer target.Close() //nolint:errcheck

	handlerCalled := make(chan struct{}, 1)
	target.Handle(func(stream ServerStream) error {
		handlerCalled <- struct{}{}
		return stream.Send([]byte("unexpected"))
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msSource.sendCh:
				if !ok {
					return
				}
				select {
				case msTarget.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-msTarget.sendCh:
				if !ok {
					return
				}
				select {
				case msSource.recvCh <- msg:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	_, err := source.Invoke(ctx, testTargetAgentId, []byte("hello"))
	if err == nil {
		t.Fatal("expected E2EE negotiation failure")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", st.Code())
	}

	select {
	case <-handlerCalled:
		t.Fatal("target handler should not have been invoked for unsupported E2EE control frame")
	default:
	}
}
