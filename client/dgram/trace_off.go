// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !relaytrace

package dgram

func traceOpen(int)                     {}
func traceRead(string, uint64, string)  {}
func traceReadDrop(string, bool)        {}
func traceRecvC(string, uint64, string) {}
func traceExpireC(uint64)               {}
func traceRecvA(string, uint64, string) {}
func traceReplyA(uint64)                {}
func traceExpireA(uint64)               {}
func traceEnd()                         {}
