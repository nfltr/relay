// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package grpcclient

import (
	"context"
	"sync"

	"github.com/nfltr/relay/proto/wire/agentwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ClientIdentity opens every call and stream of a connection with the
// protocol v1 Hello (agentwire.HelloKey: protocol version and this process's
// client identity, agentwire.Self) and the client generation
// (agentwire.GenerationKey, which a relay may require), and fails a stream whose first reply
// carries no Welcome: a relay older than protocol v1 is refused, never
// silently used.
func ClientIdentity() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			var header metadata.MD
			if err := invoker(metadata.AppendToOutgoingContext(ctx, identityPairs()...), method, req, reply, cc, append(opts, grpc.Header(&header))...); err != nil {
				return err
			}
			if !agentwire.HasWelcome(header) {
				return status.Error(codes.FailedPrecondition, agentwire.RelayTooOld)
			}
			return nil
		}),
		grpc.WithChainStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			cs, err := streamer(metadata.AppendToOutgoingContext(ctx, identityPairs()...), desc, cc, method, opts...)
			if err != nil {
				return nil, err
			}
			return &welcomeStream{ClientStream: cs}, nil
		}),
	}
}

// identityPairs is the Hello and the client generation as request
// metadata pairs.
func identityPairs() []string {
	return append(agentwire.Self().HelloPairs(), agentwire.GenerationPairs()...)
}

// welcomeStream checks the relay's Welcome once its headers have arrived,
// which the first received message proves (a server sends headers first).
type welcomeStream struct {
	grpc.ClientStream
	once sync.Once
	err  error
}

// RecvMsg fails the first message of a reply without a Welcome.
func (s *welcomeStream) RecvMsg(m any) error {
	if err := s.ClientStream.RecvMsg(m); err != nil {
		return err
	}
	s.once.Do(func() {
		if md, err := s.ClientStream.Header(); err == nil && !agentwire.HasWelcome(md) {
			s.err = status.Error(codes.FailedPrecondition, agentwire.RelayTooOld)
		}
	})
	return s.err
}
