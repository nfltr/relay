// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package agent

import "google.golang.org/grpc/metadata"

// Without the relaytrace tag the agent's Handoff recorder
// (trace_handoff_on.go) is these empty functions: the compiler drops every
// call with its arguments, and traceOn every branch only they need.
const traceOn = false

func traceANew(*lazyLink)                   {}
func traceARegister(*lazyLink, metadata.MD) {}
func traceADial(*lazyLink)                  {}
func traceABind(*lazyLink, string)          {}
func traceAGiveUp(*lazyLink)                {}
func traceAEnd(*lazyLink)                   {}
func traceAAdopt(*lazyLink, string, bool)   {}
func traceADrain(*lazyLink, string)         {}
func traceAParkDrain(*linkPark, string)     {}
func traceAOpen(*linkSessions) string       { return "" }
func traceARefused(*linkSessions, string)   {}
