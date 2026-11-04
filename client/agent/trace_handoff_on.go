// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/grpc/metadata"
)

// The agent's Handoff trace (go test -tags relaytrace, RELAYTRACE=<dir>):
// the agent's steps of relay-core's spec/Handoff.tla (lazyLink, linkPark)
// for one agent run (its linkPark; a lazyLink without a park is a run of
// one primary), to <dir>/hagent-<n>.ndjson, checked by relay-core's
// spec/TraceHandoffAgent.tla (relay-core spec/README.md "Agent-side
// Handoff traces"). Primaries are numbered 1.. in the order the agent read
// their headers, a token by the primary that first carried it, link
// sessions a1.. in the order the agent took them. Each line is written
// under traceMu inside the lock that orders its change (lazyLink.mu,
// linkPark.mu): traceMu is the innermost lock. The relay's steps are not
// logged: TLC chooses them. A run's trace ends when the agent stops.
const traceOn = true

type handoffRun struct {
	park *linkPark
	f    *os.File
	gens int
	toks map[string]int // token -> the primary that first carried it
	sess int
}

var (
	traceMu  sync.Mutex
	traceN   int
	parkRuns = map[*linkPark]*handoffRun{}     // under traceMu
	lazyRuns = map[*lazyLink]*handoffRun{}     // likewise
	lazyGens = map[*lazyLink]int{}             // a registered primary's number
	lsRuns   = map[*linkSessions]*handoffRun{} // a primary's link sessions' run
	ended    = map[*lazyLink]bool{}            // AgentEnd logged
)

func (r *handoffRun) log(ev string, g, t int, s string) {
	if r == nil || r.f == nil || r.park != nil && r.park.ctx.Err() != nil {
		return
	}
	b := fmt.Appendf(nil, `{"ev":%q,"g":%d,"t":%d,"s":%q}`+"\n", ev, g, t, s)
	if _, err := r.f.Write(b); err != nil {
		panic(err)
	}
}

// traceANew: a primary's lazyLink, in its agent's run.
func traceANew(z *lazyLink) {
	if os.Getenv("RELAYTRACE") == "" {
		return
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	r := parkRuns[z.park]
	if r == nil {
		r = &handoffRun{park: z.park, toks: map[string]int{}}
		if z.park != nil {
			parkRuns[z.park] = r
		}
	}
	lazyRuns[z], lsRuns[z.ls] = r, r
}

// traceARegister: z's primary's header md, read (once per primary) before
// any step of its link. Only a primary that asked for a link and was
// offered one is a Handoff primary.
func traceARegister(z *lazyLink, md metadata.MD) {
	traceMu.Lock()
	defer traceMu.Unlock()
	r := lazyRuns[z]
	if _, done := lazyGens[z]; r == nil || done {
		return
	}
	token := firstValue(md, tcpBindHeader)
	quicOK, tcpOK := z.dial.linkPlan(dataplane.ParseAgentLinkOffer(md.Get(dataplane.AgentLinkHeader), md.Get(dataplane.AgentLinkQUICHeader)))
	if token == "" || !quicOK && !tcpOK {
		return
	}
	if r.f == nil {
		traceN++
		f, err := os.OpenFile(filepath.Join(os.Getenv("RELAYTRACE"), "hagent-"+strconv.Itoa(traceN)+".ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- the tester's RELAYTRACE
		if err != nil {
			panic(err)
		}
		r.f = f
	}
	r.gens++
	lazyGens[z] = r.gens
	t, ok := r.toks[token]
	if !ok {
		t = r.gens
		r.toks[token] = t
	}
	r.log("Register", r.gens, t, "")
}

// zlog logs ev of z's primary (g) and token's number (t), when traced.
func zlog(z *lazyLink, ev, token string) {
	traceMu.Lock()
	defer traceMu.Unlock()
	g, ok := lazyGens[z]
	if !ok {
		return
	}
	r := lazyRuns[z]
	r.log(ev, g, r.toks[token], "")
}

// traceADial: z dials its link (lazyLink.open), under z.mu.
func traceADial(z *lazyLink) { zlog(z, "Dial", "") }

// traceABind: z's dial connected, the relay bound it, under z.mu.
func traceABind(z *lazyLink, token string) { zlog(z, "Bind", token) }

// traceAGiveUp: z's dial failed (the relay refused it), under z.mu.
func traceAGiveUp(z *lazyLink) { zlog(z, "GiveUp", "") }

// traceAEnd: z's primary ended (lazyLink.end, close), once, under z.mu.
func traceAEnd(z *lazyLink) {
	traceMu.Lock()
	e := ended[z]
	ended[z] = true
	traceMu.Unlock()
	if !e {
		zlog(z, "AgentEnd", "")
	}
}

// traceAAdopt: z adopted (ok) or refused the parked link of token, under z.mu.
func traceAAdopt(z *lazyLink, token string, ok bool) {
	ev := "AdoptRefused"
	if ok {
		ev = "Adopt"
	}
	zlog(z, ev, token)
}

// traceADrain: the agent drained the link of token: z's (lazyLink.close)
// or the park's that z's primary did not resume.
func traceADrain(z *lazyLink, token string) { zlog(z, "Drain", token) }

// traceAParkDrain: p's parked link of token drained at its TTL, under p.mu.
func traceAParkDrain(p *linkPark, token string) {
	traceMu.Lock()
	defer traceMu.Unlock()
	if r := parkRuns[p]; r != nil {
		if t, ok := r.toks[token]; ok {
			r.log("Drain", 0, t, "")
		}
	}
}

// traceAOpen: the agent took a link session (linkSessions.accept); its name.
func traceAOpen(ls *linkSessions) string {
	traceMu.Lock()
	defer traceMu.Unlock()
	r := lsRuns[ls]
	if r == nil || r.f == nil {
		return ""
	}
	r.sess++
	s := "a" + strconv.Itoa(r.sess)
	r.log("Open", 0, 0, s)
	return s
}

// traceARefused: the agent refused link session s for want of a context
// to serve it in (its own ended).
func traceARefused(ls *linkSessions, s string) {
	traceMu.Lock()
	defer traceMu.Unlock()
	if s != "" {
		lsRuns[ls].log("Refused", 0, 0, s)
	}
}
