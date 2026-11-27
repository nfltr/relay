// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package agent

type stopTracer struct{}

type stopTraceSession struct{}

func (*stopTracer) register(_ *stopTraceSession, refused func() bool) bool {
	return refused()
}
func (*stopTracer) begin(drain func() bool) (int, bool) {
	return 0, drain()
}
func (*stopTracer) drainEnd(_ int, _ bool, set func()) { set() }
func (*stopTracer) reset(int)                          {}
func (*stopTracer) end(int)                            {}

func (*stopTraceSession) targetReset()          {}
func (*stopTraceSession) abort(<-chan struct{}) {}
func (*stopTraceSession) done()                 {}
func (*stopTraceSession) cut()                  {}
