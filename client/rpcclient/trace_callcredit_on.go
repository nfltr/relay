// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package rpcclient

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/nfltr/relay/proto/pb"
)

// The CallCredit trace (go test -tags relaytrace, RELAYTRACE=<dir>): the
// rpcclient steps of relay spec/CallCredit.tla of every agent in the
// process, one NDJSON line each, to <dir>/callcredit-<pid>.ndjson, checked
// per call and direction by relay spec/TraceCallCredit.tla (spec/README.md
// "CallCredit traces"). A line names its step (ev), the call's direction
// (d: "req" the requests, "resp" the responses), the call's transaction id
// (c) and a window update's count (n). The direction follows from the step
// and the agent's role in the call (the caller sends requests, the handler
// responses), which traceCCOpen records. Each line is written before the
// step's effect can be seen by the other side (a Send before its frame
// goes out, a Deliver before its frame is in the call's buffer, a Read
// before its window update, a Grant before its credit), under ccMu, so the
// file's order is one the run took. The relay's steps are not logged: TLC
// chooses them.
type ccKey struct {
	a   *Agent
	txn string
}

var (
	ccMu    sync.Mutex
	ccFile  *os.File
	ccRoles = map[ccKey]bool{} // under ccMu: true when the agent made the call
)

// traceCCOpen: agent a opened the credit of call txn, as its caller or its handler.
func traceCCOpen(a *Agent, txn string, caller bool) {
	if os.Getenv("RELAYTRACE") == "" {
		return
	}
	ccMu.Lock()
	ccRoles[ccKey{a, txn}] = caller
	ccMu.Unlock()
}

// traceCC logs step ev of agent a in call txn (n: a Grant's count).
func traceCC(a *Agent, ev, txn string, n int) {
	ccMu.Lock()
	defer ccMu.Unlock()
	caller, ok := ccRoles[ccKey{a, txn}]
	if !ok {
		return
	}
	// The requests: what the caller sends and grants for, the handler
	// delivers and reads; the responses the other way round. Eom and
	// Cancel are the caller's, of the response direction.
	d := "resp"
	if caller == (ev == "Send" || ev == "Grant") {
		d = "req"
	}
	if ev == "Eom" || ev == "Cancel" {
		d = "resp"
	}
	if ccFile == nil {
		f, err := os.OpenFile(filepath.Join(os.Getenv("RELAYTRACE"), "callcredit-"+strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
		if err != nil {
			panic(err)
		}
		ccFile = f
	}
	if _, err := ccFile.Write(fmt.Appendf(nil, `{"ev":%q,"d":%q,"c":%q,"n":%d}`+"\n", ev, d, txn, n)); err != nil {
		panic(err)
	}
}

// The CallLifecycle trace: the target-side steps of relay
// spec/CallLifecycle.tla of every agent in the process, one NDJSON line
// each, to <dir>/calllifecycle-<pid>.ndjson, checked per transaction by
// relay spec/TraceCallLifecycle.tla. A line names its step (ev: Serve,
// Start, Drop, Refuse: the receive loop took a request frame; Return: a
// served call's entry went), the agent (a: its address, unique in the
// process), the transaction (c), and for a frame its kind
// (k: data, eom, cancel) and continuation mark (cont). The receive loop's
// decision and its line, and endServed's delete and its line, are taken
// under clMu (clLock), so the file's order is the order the entries
// changed. The caller's steps are not logged: TLC chooses them.
var (
	clMu     sync.Mutex
	clFileMu sync.Mutex
	clFile   *os.File
)

func clLock()   { clMu.Lock() }
func clUnlock() { clMu.Unlock() }

// traceCL logs step ev of agent a for transaction txn (msg: the frame the
// receive loop took; nil for Return). An empty ev is no step.
func traceCL(a *Agent, ev, txn string, msg *pb.TunnelFrame) {
	if ev == "" || os.Getenv("RELAYTRACE") == "" {
		return
	}
	k := "data"
	switch {
	case msg == nil:
		k = ""
	case msg.GetMessageType() == "cancel":
		k = "cancel"
	case msg.GetEom() && len(msg.GetPayload()) == 0:
		k = "eom"
	}
	clFileMu.Lock()
	defer clFileMu.Unlock()
	if clFile == nil {
		f, err := os.OpenFile(filepath.Join(os.Getenv("RELAYTRACE"), "calllifecycle-"+strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
		if err != nil {
			panic(err)
		}
		clFile = f
	}
	if _, err := clFile.Write(fmt.Appendf(nil, `{"ev":%q,"a":"%p","c":%q,"k":%q,"cont":%t}`+"\n", ev, a, txn, k, msg.GetContinuation())); err != nil {
		panic(err)
	}
}
