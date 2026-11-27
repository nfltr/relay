// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package p2p

// bpTrace records nothing without -tags relaytrace (browserpeer_trace_on.go).
type bpTrace struct{}

func newBPTrace(int) *bpTrace     { return nil }
func (*bpTrace) emit(string, int) {}
func (*bpTrace) close()           {}
