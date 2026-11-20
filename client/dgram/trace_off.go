// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package dgram

func traceServe(int)                    {}
func traceOpen(int)                     {}
func traceRead(string, uint64, string)  {}
func traceReadDrop(string, bool)        {}
func traceRecvC(string, uint64, string) {}
func traceExpireC(uint64)               {}
func traceRecvA(string, uint64, string) {}
func traceReplyA(uint64)                {}
func traceExpireA(uint64)               {}
func traceRecvDg(bool, uint64, string)  {}
func traceEndStep(bool, int)            {}
func traceCleanup(bool, int)            {}
func tailOut(frame) string              { return "" }

func traceSend(d Direct, p []byte, _ bool, _ string, _ uint64) error { return d.SendDatagram(p) }
