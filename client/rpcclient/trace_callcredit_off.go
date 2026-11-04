// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package rpcclient

// Without the relaytrace tag the CallCredit recorder
// (trace_callcredit_on.go) is these empty functions: the compiler drops
// every call with its arguments.
func traceCCOpen(*Agent, string, bool)    {}
func traceCC(*Agent, string, string, int) {}
