// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agent

import "syscall"

// wsaeConnRefused is Winsock's WSAECONNREFUSED, which the syscall package
// does not name.
const wsaeConnRefused syscall.Errno = 10061

// errConnRefused are the errors of a dial the target refused (Winsock's
// own code on Windows).
var errConnRefused = []error{syscall.ECONNREFUSED, wsaeConnRefused}
