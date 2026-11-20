// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgpki

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestTraceRenewGraceIsOrgpkis: TraceEnrol.tla checks recorded renewals
// against RenewGrace in seconds; it kept a week after lane SEAMLESS made the
// grace 90 days, and spec-enrol-traces stayed red (lane ENROLTRACE).
func TestTraceRenewGraceIsOrgpkis(t *testing.T) {
	b, err := os.ReadFile("../../spec/enrol/TraceEnrol.tla")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^RenewGrace == (\d+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("TraceEnrol.tla: no RenewGrace == <seconds> line")
	}
	if got, _ := strconv.Atoi(string(m[1])); got != int(RenewGrace.Seconds()) {
		t.Fatalf("TraceEnrol.tla RenewGrace = %d s, orgpki.RenewGrace = %d s", got, int(RenewGrace.Seconds()))
	}
}
