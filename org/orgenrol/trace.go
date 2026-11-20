// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !enroltrace

package orgenrol

import (
	"crypto"
	"crypto/x509"
	"time"

	"github.com/nfltr/relay/org/orgpki"
)

// traceNotice, traceRead and tracePublish record the issuer service's
// steps of spec/enrol/RevokePush.tla (README "Traces"): a file-change
// notice (with the CRL then in dir), the CRL maintain read under the
// lock, the CRL it published. Built only with -tags enroltrace
// (trace_on.go); here they compile away.
func traceNotice(string)          {}
func traceRead(string, []byte)    {}
func tracePublish(string, []byte) {}

// tracePut and traceCarry record spec/enrol/CrlCarriers.tla's PutCopy (the
// issuer's put of the relay's copy, logged before it is sent) and a
// machine's take of a CRL message through a carrier ("mailbox" or
// "copy": Push, ReadCopy), checked by TraceCrlCarriers.tla; built only
// with -tags enroltrace.
func tracePut(string, []byte)                                {}
func traceCarry(string, any, []byte, time.Time, bool, error) {}

// traceJoinRoot, traceJoinStart and traceJoinEnd record a join's steps of
// spec/enrol/Join.tla (README "Traces"): the root check (Start's Trusts),
// a run's request with the key it keeps for the token, and how the run
// ended (Install, or GiveUp); checked by TraceJoin.tla, built only with
// -tags enroltrace.
func traceJoinRoot(string, Pins, *x509.Certificate, *x509.Certificate, bool)  {}
func traceJoinStart(string, string, string, crypto.PublicKey, string, string) {}
func traceJoinEnd(string, string, string, string, orgpki.Answer)              {}
