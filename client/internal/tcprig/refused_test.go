// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package tcprig

import (
	"errors"
	"net"
	"runtime"
	"syscall"
	"testing"
)

// TestRefusedAddrHoldsItsPort: every dial to RefusedAddr is refused and,
// on Linux (the CI runners), no listener can take its port while the test
// runs (a port probed free and closed could be taken by any process). macOS lets a listener that names the port share it with the
// connection (BSD SO_REUSEADDR); a port picked for :0, as tests listen,
// skips it there too.
func TestRefusedAddrHoldsItsPort(t *testing.T) {
	addr := RefusedAddr(t)
	if ln, err := net.Listen("tcp", addr.String()); err == nil {
		_ = ln.Close()
		if runtime.GOOS == "linux" {
			t.Fatalf("a listener took %s: its port is not held", addr)
		}
	}
	for range 3 {
		c, err := net.Dial("tcp", addr.String())
		if err == nil {
			_ = c.Close()
			t.Fatalf("dial %s connected; want refused", addr)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("dial %s: %v; want connection refused", addr, err)
		}
	}
}
