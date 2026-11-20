// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build relaytrace

package dgram

import (
	"errors"
	"fmt"

	"github.com/nfltr/relay/client/internal/dgtrace"
)

// The DatagramAssoc trace (go test -tags relaytrace, RELAYTRACE=<dir>):
// the steps of relay spec/DatagramAssoc.tla both sides of an association
// take, one NDJSON line each, to client/internal/dgtrace's file, checked
// by spec/TraceDatagramAssoc.tla (spec/README.md "DatagramAssoc traces").
// Each line is written in the critical section of its step (the side's
// lock), so a frame's line comes before its receiver's, and the lines of
// one side's frames are in its stream order; a datagram that may go
// direct is recorded by the sender as it sends it (traceSend), with the
// carrier it took. Recording stops at the association's end (its cut is
// not traced). A line names the step (ev), the flow id (f), a source (s,
// with whether it is admitted: adm), a frame's kind (k), what the side
// did with it (out) and the carrier of a datagram (op, out).
func trace(line string) { dgtrace.Line(line) }

func traceServe(maxFlows int) { trace(fmt.Sprintf(`{"ev":"Serve","n":%d}`, maxFlows)) }
func traceOpen(maxFlows int)  { trace(fmt.Sprintf(`{"ev":"AssocOpen","n":%d}`, maxFlows)) }
func readLine(src string, f uint64, op string) string {
	return fmt.Sprintf(`{"ev":"Read","s":%q,"adm":true,"f":%d,"op":%q}`, src, f, op)
}
func traceRead(src string, f uint64, op string) { trace(readLine(src, f, op)) }
func traceReadDrop(src string, adm bool) {
	trace(fmt.Sprintf(`{"ev":"Read","s":%q,"adm":%v,"f":0,"op":"drop"}`, src, adm))
}
func traceRecvC(k string, f uint64, out string) {
	trace(fmt.Sprintf(`{"ev":"RecvC","k":%q,"f":%d,"out":%q}`, k, f, out))
}
func traceExpireC(f uint64) { trace(fmt.Sprintf(`{"ev":"ExpireC","f":%d}`, f)) }
func traceRecvA(k string, f uint64, out string) {
	trace(fmt.Sprintf(`{"ev":"RecvA","k":%q,"f":%d,"out":%q}`, k, f, out))
}
func replyLine(f uint64, out string) string {
	return fmt.Sprintf(`{"ev":"ReplyA","f":%d,"out":%q}`, f, out)
}
func traceReplyA(f uint64)  { trace(replyLine(f, "stream")) }
func traceExpireA(f uint64) { trace(fmt.Sprintf(`{"ev":"ExpireA","f":%d}`, f)) }
func traceRecvDg(client bool, f uint64, out string) {
	ev := "RecvDgA"
	if client {
		ev = "RecvDgC"
	}
	trace(fmt.Sprintf(`{"ev":%q,"f":%d,"out":%q}`, ev, f, out))
}
func traceEnd() { dgtrace.End() }

// traceSend sends p on d (flow f's datagram from src at the client, a
// reply at the agent) and records the step with the carrier it took:
// direct, the stream (after the path's loss when d found it), or spilled
// to the stream; under the trace's lock, so the far end's line comes
// after.
func traceSend(d Direct, p []byte, client bool, src string, f uint64) error {
	if !dgtrace.On() {
		return d.SendDatagram(p)
	}
	dgtrace.Lock()
	defer dgtrace.Unlock()
	err := d.SendDatagram(p)
	out := "direct"
	switch {
	case err == nil:
	case errors.Is(err, ErrNotDirect):
		out = "stream"
		if errors.Is(err, dgtrace.ErrLost) {
			dgtrace.LineLocked(`{"ev":"PathLoss"}`)
		}
	default:
		out = "spill"
	}
	if !client {
		dgtrace.LineLocked(replyLine(f, out))
		return err
	}
	if out == "stream" {
		out = "d"
	}
	dgtrace.LineLocked(readLine(src, f, out))
	return err
}
