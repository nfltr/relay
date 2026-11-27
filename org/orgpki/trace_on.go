// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build enroltrace

package orgpki

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Trace mode (go test -tags enroltrace, ENROLTRACE=<dir>) appends one JSON
// line per step to <dir>/<pid>.ndjson; scripts/spec-enrol.sh traces checks
// it with spec/enrol/TraceEnrol.tla. The issuer writes under its lock and a
// verifier under its own, so each one's lines are in its order.
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

// Move traces (ORGMOVETRACE=<dir>, scripts/spec-orgmove.sh traces): every
// commit of an issuer, by its line's hash and the hash before it, and a
// move's send; spec/orgmove/TraceOrgMove.tla checks them.
var moveMu sync.Mutex

func traceCommit(orgID string, e Entry, prev, head string) {
	peopleTrace(orgID, e)
	ev := "act"
	switch e.Act {
	case ActMoved:
		ev = "fence"
	case ActArrived:
		return // TraceImport, once the import's log is written
	}
	moveTrace(map[string]any{"ev": ev, "o": orgID, "act": e.Act, "k": e.Key, "num": e.Number, "p": prev, "h": head})
}

func moveTrace(l map[string]any) {
	dir := os.Getenv("ORGMOVETRACE")
	if dir == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	moveMu.Lock()
	defer moveMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

// App enrolment traces (APPENROLTRACE=<dir>, scripts/spec-appenrol.sh
// traces): the issuer's sign-in, code, renewal and revocation steps,
// written under its lock; spec/appenrol/TraceAppEnrol.tla checks them.
var appMu sync.Mutex

func appTraceLine(l map[string]any) {
	dir := os.Getenv("APPENROLTRACE")
	if dir == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	appMu.Lock()
	defer appMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

// People traces (PEOPLETRACE=<dir>, scripts/spec-people.sh traces): the
// issuer's log lines of the people layer as it commits them (an invite, a
// join, a person's certificate, a role, a removal, a name's or an app's
// revoke); spec/people/TracePeople.tla checks them.
var peopleMu sync.Mutex

func peopleTrace(orgID string, e Entry) {
	dir := os.Getenv("PEOPLETRACE")
	if dir == "" {
		return
	}
	l := map[string]any{"o": orgID, "u": e.Person, "t": e.Time.Unix()}
	switch {
	case e.Act == ActInvite:
		l["ev"], l["by"], l["ar"], l["r"], l["id"], l["exp"] = "invite", e.Actor, e.ActorRole, e.Role, e.Invite, e.NotAfter.Unix()
	case e.Act == ActIssued && e.Invite != "":
		l["ev"], l["r"], l["id"], l["n"], l["a"] = "join", e.Role, e.Invite, e.Name, e.App
	case (e.Act == ActIssued || e.Act == ActRenewed || e.Act == ActRebound || e.Act == ActAdopted) && e.Person != "":
		l["ev"], l["n"], l["mid"], l["a"] = "add", e.Name, e.MachineID, e.App
	case e.Act == ActRole:
		l["ev"], l["by"], l["ar"], l["r"] = "role", e.Actor, e.ActorRole, e.Role
	case e.Act == ActRevoked && e.Person != "":
		f := [][]string{}
		for _, x := range e.Filed {
			f = append(f, []string{x.Name, x.MachineID})
		}
		l["ev"], l["by"], l["ar"], l["sr"], l["f"] = "remove", e.Actor, e.ActorRole, e.Role, f
	case e.Act == ActRevoked:
		l["ev"], l["n"], l["a"] = "revoke", e.Name, e.App
	default:
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	peopleMu.Lock()
	defer peopleMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

// grantLine (GRANTTRACE=<dir>) appends one grant step of the issuer to
// <dir>/<pid>.ndjson, beside client/orgid's grant checks, for
// spec/grant/TraceGrant.tla. The issuer writes under its lock; one write
// per line (O_APPEND) keeps the two writers' lines whole.
func grantLine(l map[string]any) {
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

// Group traces (GROUPTRACE=<dir>, scripts/spec-onegroup.sh traces): the
// issuer's move orders and signed statuses, under its lock, in its order;
// spec/onegroup/TraceGroupIssuer.tla checks them.
var groupMu sync.Mutex

func groupLine(l map[string]any) {
	dir := os.Getenv("GROUPTRACE")
	if dir == "" {
		return
	}
	b, err := json.Marshal(l)
	if err != nil {
		panic(err)
	}
	groupMu.Lock()
	defer groupMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(os.Getpid())+".ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		panic(err)
	}
}

// groupStatusLine records a signed status: each member's groups and
// serial, and the CRL it carries.
func groupStatusLine(st Status) {
	m := map[string]any{}
	for _, x := range st.Members {
		m[x.Name] = map[string]any{"gs": append([]string{}, x.Groups...), "s": x.Serial}
	}
	groupLine(map[string]any{"ev": "sign", "o": st.OrgID, "num": st.CRL.Number, "map": m, "t": st.At.Unix()})
}
