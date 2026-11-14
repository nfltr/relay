// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !enroltrace

package orgid

// traceLine records one step of a verifier
// (nfltr spec/enrol/README.md "Traces"): the line's fields as TraceEnrol.tla
// reads them. Built only with -tags enroltrace (trace_on.go); here it
// compiles away.
func traceLine(map[string]any) {}
