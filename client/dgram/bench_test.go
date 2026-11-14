// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dgram

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// BenchmarkDatagramAssocRoundTrip is one flow's datagram to an in-process
// echo target and back over one association (the profiles' series, nfltr
// AGENTS.md "Profiling Evidence").
func BenchmarkDatagramAssocRoundTrip(b *testing.B) {
	for _, size := range []int{64, 1200} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			s, c := net.Pipe()
			go func() {
				_ = Serve(context.Background(), s, Config{}, func() (net.Conn, error) {
					x, y := Pipe(64, nil, nil)
					go func() {
						buf := make([]byte, MaxDatagram)
						for {
							n, err := y.Read(buf)
							if err != nil {
								return
							}
							_, _ = y.Write(buf[:n])
						}
					}()
					return x, nil
				})
			}()
			cl := NewClient(c, Config{})
			defer cl.Close() //nolint:errcheck
			f, err := cl.Dial(nil, nil)
			if err != nil {
				b.Fatal(err)
			}
			_ = f.SetReadDeadline(time.Now().Add(time.Minute))
			p, buf := make([]byte, size), make([]byte, MaxDatagram)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := f.Write(p); err != nil {
					b.Fatal(err)
				}
				if _, err := f.Read(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
