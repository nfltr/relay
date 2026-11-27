// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

// TestOrgSessionThroughputBench (NFLTR_BENCH=1) is a benchmark in a test
// (its setup is the org tests' helpers, which take *testing.T): one
// organisation-mode session through the agent's org path (a relayed link
// session, TLS ended by the agent, the echo), 32 KiB written and read back
// per op. It prints a benchstat line; -cpuprofile and -memprofile apply.
// Lane DIRECTPATH3: the base and after of the direct paths' agent change.
func TestOrgSessionThroughputBench(t *testing.T) {
	if os.Getenv("NFLTR_BENCH") == "" {
		t.Skip("a benchmark: NFLTR_BENCH=1")
	}
	o := newTestOrg(t)
	web := o.agentOrg(o.machine(t, "web", nil, time.Hour, false))
	client := o.machine(t, "laptop", []string{"db"}, time.Hour, false)
	l := orgSessions(t, web, "db")
	tc, err := orgSession(t, l, "db", &client)
	if err != nil {
		t.Fatal(err)
	}
	_ = tc.SetDeadline(time.Time{})
	buf, got := make([]byte, 32<<10), make([]byte, 32<<10)
	r := testing.Benchmark(func(b *testing.B) {
		b.SetBytes(int64(len(buf)))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := tc.Write(buf); err != nil {
				b.Fatal(err)
			}
			if _, err := io.ReadFull(tc, got); err != nil {
				b.Fatal(err)
			}
		}
	})
	fmt.Printf("BenchmarkOrgSessionEcho32K\t%s\t%s\n", r.String(), r.MemString())
}
