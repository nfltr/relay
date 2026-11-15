// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !enroltrace

package orgenrol

// traceNotice, traceRead and tracePublish record the issuer service's
// steps of spec/enrol/RevokePush.tla (README "Traces"): a file-change
// notice (with the CRL then in dir), the CRL maintain read under the
// lock, the CRL it published. Built only with -tags enroltrace
// (trace_on.go); here they compile away.
func traceNotice(string)          {}
func traceRead(string, []byte)    {}
func tracePublish(string, []byte) {}
