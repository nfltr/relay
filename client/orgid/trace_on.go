// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build enroltrace

package orgid

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Trace mode (go test -tags enroltrace, ENROLTRACE=<dir>) appends one JSON
// line per step to <dir>/<pid>.ndjson; scripts/spec-enrol.sh
// traces checks it with spec/enrol/TraceEnrol.tla. A verifier writes under
// its lock, so its lines are in its order.
var traceMu sync.Mutex

func traceLine(l map[string]any) {
	dir := os.Getenv("ENROLTRACE")
	if dir == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

// traceCarry appends a CRL message's take through carrier via to
// <dir>/<pid>.crlcarriers ({"ev": "take", "via", "v": the identity, "k":
// the CRL's authority key id, "num", "next", "t", "res": taken, same (the
// CRL held already) or refused}); scripts/spec-enrol.sh traces checks it
// with spec/enrol/TraceCrlCarriers.tla.
func traceCarry(via string, m any, der []byte, t time.Time, took bool, err error) {
	res := "same"
	switch {
	case err != nil:
		res = "refused"
	case took:
		res = "taken"
	}
	l := map[string]any{"ev": "take", "via": via, "v": fmt.Sprintf("%p", m), "k": "", "num": int64(0), "next": int64(0), "t": t.Unix(), "res": res}
	if c, perr := x509.ParseRevocationList(der); perr == nil && c.Number != nil {
		l["k"], l["num"], l["next"] = hex.EncodeToString(c.AuthorityKeyId), c.Number.Int64(), c.NextUpdate.Unix()
	}
	carryLine(l)
}

func carryLine(l map[string]any) {
	dir := os.Getenv("ENROLTRACE")
	if dir == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(os.Getpid())+".crlcarriers"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

// grantTrace (GRANTTRACE=<dir>) appends a grant check's line to
// <dir>/<pid>.ndjson, beside the issuer's (relay org orgpki), for
// spec/grant/TraceGrant.tla. One write per line (O_APPEND): the two
// writers' lines stay whole.
func grantTrace(l map[string]any) {
	dir := os.Getenv("GRANTTRACE")
	if dir == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}
