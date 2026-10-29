// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// OutgoingMetadata is a small builder for gRPC outgoing request metadata. It
// lets CLI callers attach headers (API keys, agent identity, labels, etc.) to
// a context without importing google.golang.org/grpc/metadata directly.
type OutgoingMetadata struct {
	md metadata.MD
}

// NewOutgoingMetadata returns an empty metadata builder.
func NewOutgoingMetadata() *OutgoingMetadata {
	return &OutgoingMetadata{md: metadata.MD{}}
}

// Set assigns a single value for key, replacing any prior value(s) for key.
func (m *OutgoingMetadata) Set(key, value string) *OutgoingMetadata {
	m.md.Set(key, value)
	return m
}

// Context attaches the accumulated metadata to ctx as outgoing gRPC metadata.
func (m *OutgoingMetadata) Context(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, m.md)
}
