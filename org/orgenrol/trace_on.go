// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build enroltrace

package orgenrol

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/orgissuer"
	"github.com/nfltr/relay/org/orgpki"
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

func traceRead(dir string, crl []byte) { pushTrace("read", dir, crl) }
func tracePublish(dir string, crl []byte) {
	pushTrace("publish", dir, crl)
	carryLine(crlLine("publish", dir, crl))
}

// tracePut logs the issuer directory dir's put of crl on the relay's copy
// to <pid>.crlcarriers (TraceCrlCarriers.tla), with its publishes beside
// it.
func tracePut(dir string, crl []byte) { carryLine(crlLine("put", dir, crl)) }

// traceCarry logs machine m's take of CRL der through carrier via at t to
// <pid>.crlcarriers: res taken, same (held already) or refused.
func traceCarry(via string, m any, der []byte, t time.Time, took bool, err error) {
	res := "same"
	switch {
	case err != nil:
		res = "refused"
	case took:
		res = "taken"
	}
	l := crlLine("take", "", der)
	delete(l, "d")
	l["via"], l["v"], l["t"], l["res"] = via, fmt.Sprintf("%p", m), t.Unix(), res
	carryLine(l)
}

// crlLine is ev's line for CRL der: its issuer's key id (k), Number and
// NextUpdate.
func crlLine(ev, dir string, der []byte) map[string]any {
	l := map[string]any{"ev": ev, "d": dir, "k": "", "num": int64(0), "next": int64(0)}
	if c, err := x509.ParseRevocationList(der); err == nil && c.Number != nil {
		l["k"], l["num"], l["next"] = hex.EncodeToString(c.AuthorityKeyId), c.Number.Int64(), c.NextUpdate.Unix()
	}
	return l
}

func carryLine(l map[string]any) {
	out := os.Getenv("ENROLTRACE")
	if out == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(out, strconv.Itoa(os.Getpid())+".crlcarriers"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

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

// The join's steps of spec/enrol/Join.tla, to <pid>.ndjson beside the
// issuer's lines (orgpki's trace_on.go), checked by TraceJoin.tla. Each
// line is one append of the whole line (O_APPEND), and a join's request
// is logged before it is posted, its end after its answer was read, so a
// line of the issuer's answer to it falls between them.

// traceJoinRoot logs the join's check of the root the relay gave
// (Join.tla Start's Trusts): own when it is the owner's, the pinned root or
// one the pinned recovery key certifies (decided here, apart from trust),
// ok when trust took it.
func traceJoinRoot(orgID string, pins Pins, root, rec *x509.Certificate, notBefore time.Time, ok bool) {
	own := orgid.Fingerprint(rec) == pins.Recovery && !root.NotBefore.Before(notBefore) &&
		(orgid.Fingerprint(root) == pins.Root || rotatedRoot(root, rec, orgID) == nil)
	joinLine(map[string]any{"ev": "jroot", "o": orgID, "own": own, "ok": ok})
}

// traceJoinStart logs a join run's request (Start): machine directory m,
// the token, the key it asks for, the run's request id and the first
// run's.
func traceJoinStart(orgID, dir, tok string, pub crypto.PublicKey, run, first string) {
	joinLine(map[string]any{"ev": "jstart", "o": orgID, "m": dir, "tok": tok, "k": orgid.KeyFingerprint(pub), "run": run, "first": first})
}

// traceJoinEnd logs how the run ended: joined (Install of answer id, for
// key ak), refused (Install of a refusal) or failed (GiveUp: no answer,
// or one the checks did not take).
func traceJoinEnd(orgID, dir, tok, res string, a orgpki.Answer) {
	ak := ""
	if c, err := x509.ParseCertificate(a.Cert); err == nil {
		ak = orgid.KeyFingerprint(c.PublicKey)
	}
	joinLine(map[string]any{"ev": "jend", "o": orgID, "m": dir, "tok": tok, "res": res, "id": a.ID, "ak": ak})
}

func joinLine(l map[string]any) {
	out := os.Getenv("ENROLTRACE")
	if out == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(out, strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

// The issuer's steps of spec/orgmove/OrgHolds.tla, to <pid>.holds under
// ORGMOVETRACE, checked by TraceOrgHolds.tla, one line each under traceMu
// ({"ev", "o": the organisation, "d": the issuer directory, "n": a
// round's publishes}): start (Run took the serve lock), read (maintain's
// read, under the directory's lock), write (the round's end: n publishes
// landed since its read), stop (Run returned at the fence, ErrMoved) or
// exit (any other return), lock (HoldServeLock took the serve lock: "o"
// unknown there) and release (ReleaseHolds gave the holds up: "d"
// unknown there). An end is logged before the serve lock is released, a
// lock after it is taken, so their order is the run's.
func traceHold(ev, org, dir string) { holdLine(map[string]any{"ev": ev, "o": org, "d": dir}) }

func traceHoldWrite(org, dir string, n int) {
	holdLine(map[string]any{"ev": "write", "o": org, "d": dir, "n": n})
}

func traceHoldEnd(org, dir string, err error) {
	ev := "exit"
	if errors.Is(err, orgpki.ErrMoved) {
		ev = "stop"
	}
	traceHold(ev, org, dir)
}

func holdLine(l map[string]any) {
	out := os.Getenv("ORGMOVETRACE")
	if out == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(out, strconv.Itoa(os.Getpid())+".holds"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}
