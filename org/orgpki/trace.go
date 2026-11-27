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

// appTraceLine records one step of the issuer for
// spec/appenrol/TraceAppEnrol.tla (scripts/spec-appenrol.sh traces).
// Built only with -tags enroltrace (trace_on.go, APPENROLTRACE=<dir>);
// here it compiles away.
func appTraceLine(map[string]any) {}

// grantLine records one grant step of the issuer for
// spec/grant/TraceGrant.tla (scripts/spec-grant.sh traces). Built only
// with -tags enroltrace (trace_on.go, GRANTTRACE=<dir>); here it compiles
// away.
func grantLine(map[string]any) {}

// groupLine records one issuer step of spec/onegroup/TraceGroupIssuer.tla
// (a move order applied, a status signed). Built only with -tags
// enroltrace (trace_on.go, GROUPTRACE=<dir>); here it compiles away.
func groupLine(map[string]any) {}
func groupStatusLine(Status)   {}
