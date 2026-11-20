// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !enroltrace

package orgid

import "time"

// traceLine records one step of a verifier
// (spec/enrol/README.md "Traces"): the line's fields as TraceEnrol.tla
// reads them. Built only with -tags enroltrace (trace_on.go); here it
// compiles away.
func traceLine(map[string]any) {}

// traceCarry records a CRL message's take through a carrier (via:
// "mailbox", the push; "copy", the relay's copy) for
// spec/enrol/TraceCrlCarriers.tla (README "Traces"); built only with
// -tags enroltrace.
func traceCarry(string, any, []byte, time.Time, bool, error) {}
