// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package dgtrace is the DatagramAssoc trace's file (relay
// spec/TraceDatagramAssoc.tla), shared by client/dgram (an association's
// steps) and client/agent (the direct path's binds), so that every step
// of a traced process lands in one file in the order taken. Without the
// relaytrace tag it holds only ErrLost.
package dgtrace

import "errors"

// ErrLost marks a direct carrier's refusal (it also is dgram.ErrNotDirect)
// when the direct path it was bound on is gone: returned once per binding,
// so the trace records the path's loss (DatagramAssoc PathLoss) where the
// sender found it.
var ErrLost = errors.New("dgram: the direct path was lost")
