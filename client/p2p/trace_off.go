// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package p2p

// traceOn is false without -tags relaytrace: SignalConn records nothing
// (trace_on.go, spec/README.md "Trace validation").
const traceOn = false

func traceJoin(*SignalConn, int)                  {}
func traceWrite(*SignalConn, uint64, []pathEntry) {}
func traceRecv(*SignalConn, int, uint64)          {}
func traceDrop(*SignalConn, int)                  {}
