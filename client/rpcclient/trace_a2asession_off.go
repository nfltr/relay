// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package rpcclient

// Without the relaytrace tag the A2ASession recorder
// (trace_a2asession_on.go) is this empty function: the compiler drops
// every call with its arguments.
func traceAS(string, string, string, string, []byte, uint64, []byte) {}
