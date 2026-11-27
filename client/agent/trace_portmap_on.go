// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// The PortMap trace (go test -tags relaytrace, RELAYTRACE=<dir>): one
// direct endpoint's steps of relay spec/PortMap.tla, one NDJSON line each,
// to <dir>/portmap-<pid>-<n>.ndjson (opened at its first step), checked by
// spec/TracePortMap.tla (spec/README.md "PortMap traces"). Every line is
// written under the portMap's lock, in the order the steps were taken.
// The gateway's table, its leases and its changes are not logged: TLC
// chooses them.
type portMapTrace struct{ f *os.File }

// line logs step ev of protocol proto; del: a delete of the held mapping
// was sent with it; life: the lease asked.
func (t *portMapTrace) line(ev, proto string, del bool, life uint32) {
	dir := os.Getenv("RELAYTRACE")
	if dir == "" {
		return
	}
	if t.f == nil {
		name := fmt.Sprintf("portmap-%s-%d.ndjson", strconv.Itoa(os.Getpid()), punchTraces.Add(1))
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
		if err != nil {
			panic(err)
		}
		t.f = f
	}
	b, err := json.Marshal(map[string]any{"ev": ev, "p": proto, "del": del, "life": life})
	if err != nil {
		panic(err)
	}
	if _, err := t.f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

func (t *portMapTrace) end() {
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
}
