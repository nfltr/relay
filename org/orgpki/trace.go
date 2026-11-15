// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !enroltrace

package orgpki

// traceLine records one step of the issuer or a verifier
// (spec/enrol/README.md "Traces"): the line's fields as TraceEnrol.tla
// reads them. Built only with -tags enroltrace (trace_on.go); here it
// compiles away.
func traceLine(map[string]any) {}

// traceCommit and moveTrace record the issuer's commits and a move's send
// (spec/orgmove/TraceOrgMove.tla). Built only with -tags enroltrace
// (trace_on.go, ORGMOVETRACE=<dir>); here they compile away.
func traceCommit(string, Entry, string, string) {}
func moveTrace(map[string]any)                  {}
