// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package agent

import "syscall"

// errConnRefused are the errors of a dial the target refused.
var errConnRefused = []error{syscall.ECONNREFUSED}
