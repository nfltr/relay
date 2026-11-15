// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build enroltrace

package orgenrol

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/nfltr/relay/org/orgissuer"
)

// Trace mode (go test -tags enroltrace, ENROLTRACE=<dir>) appends the
// service's RevokePush.tla steps to <dir>/<pid>.revokepush, one JSON line
// each ({"ev", "d", "k", "num"}: the directory, the CRL's issuer key and
// Number); scripts/spec-enrol.sh traces
// checks them with spec/enrol/TraceRevokePush.tla. A read is logged under
// the issuer directory's lock, a notice after the write it reports, so a
// notice logged before a read is of a write the read saw.
var traceMu sync.Mutex

func traceNotice(dir string) {
	der, _ := os.ReadFile(filepath.Join(dir, orgissuer.CRLFile)) // #nosec G304 -- the issuer's own directory
	pushTrace("notice", dir, der)
}

func traceRead(dir string, crl []byte)    { pushTrace("read", dir, crl) }
func tracePublish(dir string, crl []byte) { pushTrace("publish", dir, crl) }

// pushTrace logs ev of the issuer directory dir (d) for CRL der: its
// Number (num) and its issuer's key id (k; a rotation's new issuer
// numbers its CRLs afresh).
func pushTrace(ev, dir string, der []byte) {
	out := os.Getenv("ENROLTRACE")
	if out == "" {
		return
	}
	var num int64
	var k string
	if c, err := x509.ParseRevocationList(der); err == nil && c.Number != nil {
		num, k = c.Number.Int64(), hex.EncodeToString(c.AuthorityKeyId)
	}
	b, err := json.Marshal(map[string]any{"ev": ev, "d": dir, "k": k, "num": num})
	if err != nil {
		panic(err)
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(out, strconv.Itoa(os.Getpid())+".revokepush"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}
