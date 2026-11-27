// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !audittrace

package orgaudit

import "os"

func (*Log) trace(string, string, string, uint64) {}
func (*Log) traceHeld(string, string)             {}
func (*Log) traceCrash(unlock func()) func()      { return unlock }
func traceWrite(uint64)                           {}
func traceShip(string, *os.File, int64)           {}
func traceRotate(string, []byte)                  {}
