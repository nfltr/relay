// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package rpcclient

import "github.com/nfltr/relay/proto/pb"

// Without the relaytrace tag the CallCredit recorder
// (trace_callcredit_on.go) is these empty functions: the compiler drops
// every call with its arguments.
func traceCCOpen(*Agent, string, bool)    {}
func traceCC(*Agent, string, string, int) {}

// The CallLifecycle recorder (trace_callcredit_on.go) without the tag.
func clLock()                                         {}
func clUnlock()                                       {}
func traceCL(*Agent, string, string, *pb.TunnelFrame) {}
