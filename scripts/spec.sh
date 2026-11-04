#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# spec.sh check|mutants: the TLA+ models of spec/ (spec/README.md).
#   check    TLC on spec/SignalConn.cfg, spec/CallCredit.cfg,
#            spec/CallCreditBoth.cfg and spec/CallCreditSenders.cfg: their
#            invariants and liveness
#            (LARGE=1 adds CallCreditLarge.cfg, CallCreditBothLarge.cfg).
#   mutants  each bug put back must be caught.
#   traces   client/p2p's SignalConn tests (TRACE_TESTS) run with -tags
#            relaytrace; each trace, per direction that wrote, checked
#            against spec/TraceSignalConn.tla; each spec/testdata/reject-*
#            fixture rejected, each accept-* fixture accepted; every event
#            TraceCallCredit.tla takes recorded by client/rpcclient.
#   cctraces FILE...  each call and direction of each recorded CallCredit
#            trace (client/rpcclient -tags relaytrace) checked against
#            spec/TraceCallCredit.tla.
# COVERAGE=1 adds -coverage 1. Java and tla2tools.jar come from
# scripts/fetch-tla.sh.
set -eu
cd "$(dirname "$0")/.."
tools=$(scripts/fetch-tla.sh)
java=$(echo "$tools" | sed -n 1p)
jar=$(echo "$tools" | sed -n 2p)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

tlc() {
	c=$1 mod=$2
	shift 2
	cov=
	[ -z "${COVERAGE:-}" ] || cov="-coverage 1"
	(cd spec && "$java" -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 2 $cov \
		-deadlock -noGenerateSpecTE -metadir "${META:-$work/states}" -config "$c" "$@" "$mod")
}

# trace FILE W R: TLC on one recorded trace's direction W to R
# (spec/TraceSignalConn.tla); 0 when accepted. FILE's TLC output: FILE.W.out.
trace() {
	cfg=$work/$(basename "$1").$2.cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    W = $2
    R = $3
    N <- TraceN
    MaxBreak = 4
    MaxStall = 0
    Replay = TRUE
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TraceNotDone
    NoSilentLoss
    EndedFinal
    ReadBound
    PathOrdered
CFG
	META=$work/states-$(basename "$1").$2 tlc "$cfg" TraceSignalConn.tla >"$1.$2.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.$2.out"
}

# cctrace FILE D C: TLC on call C's direction D (req, resp) of a recorded
# CallCredit trace (spec/TraceCallCredit.tla); 0 when accepted. Its TLC
# output: FILE.D.C.out. The windows are rpcclient's: RequestWindow 16,
# ResponseWindow 256.
cctrace() {
	w=16
	[ "$2" = req ] || w=256
	cfg=$work/$(basename "$1").$2.$3.cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Dir = "$2"
    Call = "$3"
    Calls <- TraceCalls
    Stuck = {}
    W = $w
    N <- TraceLen
    P <- TraceLen
    Q <- TraceLen
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TraceNotDone
    TypeOK
    NoHOL
    BufferBound
    Conservation
    GrantBound
    Ordered
CFG
	META=$work/states-$(basename "$1").$2.$3 tlc "$cfg" TraceCallCredit.tla >"$1.$2.$3.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.$2.$3.out"
}

# cctraces FILE: each call and direction of a CallCredit trace; prints one
# line each, fails on a rejected one or none.
cctraces() {
	n=0 bad=0
	for dc in $(sed -E 's/.*"d":"([a-z]+)","c":"([^"]+)".*/\1:\2/' "$1" | sort -u); do
		dir=${dc%%:*} call=${dc#*:} # not d, c: tlc's
		n=$((n + 1))
		if cctrace "$1" "$dir" "$call"; then
			echo "trace $(basename "$1") $call $dir: $(grep -c "\"d\":\"$dir\",\"c\":\"$call\"" "$1") lines: accepted"
		else
			bad=$((bad + 1))
			echo "trace $(basename "$1") $call $dir: REJECTED"
			grep -E 'Error|unknown event' "$1.$dir.$call.out" | head -5
		fi
	done
	echo "$n call directions, $bad rejected"
	[ "$n" -gt 0 ] && [ "$bad" = 0 ]
}

fail=0
case ${1:-} in
check)
	cfgs="SignalConn CallCredit CallCreditBoth CallCreditSenders"
	[ -z "${LARGE:-}" ] || cfgs="$cfgs CallCreditLarge CallCreditBothLarge"
	for c in $cfgs; do
		m=${c%Large}
		echo "== $c.cfg"
		st=0
		tlc $c.cfg $m.tla >"$work/out" 2>&1 || st=$?
		grep -E '^[0-9]+ states generated|depth of|Error|violated' "$work/out" || true
		[ -z "${COVERAGE:-}" ] || grep -E '^<[A-Za-z]+.*>: 0:0$' "$work/out" | sed 's/^/never taken: /' || true
		[ $st = 0 ] || { tail -60 "$work/out"; exit $st; }
	done
	;;
mutants)
	# expect NAME SED...: $model.cfg edited must violate a property.
	model=SignalConn
	expect() {
		name=$1
		shift
		sed "$@" spec/$model.cfg >"$work/Mutant.cfg"
		if tlc "$work/Mutant.cfg" $model.tla >"$work/m.out" 2>&1; then
			echo "$name: not caught"
			fail=1
		elif grep -qE '^Error: (Invariant .* is violated|Temporal propert.* was violated)' "$work/m.out"; then
			echo "$name: caught: $(grep -m1 -E '^Error: (Invariant|Temporal)' "$work/m.out" | sed 's/^Error: //')"
		else
			echo "$name: TLC failed:"
			tail -20 "$work/m.out"
			fail=1
		fi
	}
	# P1 put back: a joining path carries only later frames.
	expect P1:no-replay -e 's/Replay = TRUE/Replay = FALSE/'
	expect P1:no-replay-stall -e 's/Replay = TRUE/Replay = FALSE/' -e '/NoSilentLoss/d'
	expect one-path -e 's/Mutant = "none"/Mutant = "one-path"/'
	# M1 (review r2) put back: the relay path's write waits for credit with no bound.
	expect M1:unbounded-relay -e 's/Mutant = "none"/Mutant = "unbounded-relay"/'
	expect witness:Stall -e 's/^    NoSilentLoss$/    W_Stall/'
	expect reorder -e 's/Mutant = "none"/Mutant = "reorder"/'
	expect witness:PathOrdered -e 's/^    PathOrdered$/    W_PathOrdered/'
	expect witness:ReadBound -e 's/^    ReadBound$/    W_ReadBound/'
	expect witness:NoSilentLoss -e 's/^    NoSilentLoss$/    W_NoSilentLoss/'
	# M2 (review r2) put back: the responder's close sent nothing.
	expect M2:one-sided -e 's/Mutant = "none"/Mutant = "one-sided"/'
	expect witness:OneSided -e 's/^    TypeOK$/    W_OneSided/'
	# L1 (review r2): a path joining a reader that ended.
	expect L1:revive -e 's/Mutant = "none"/Mutant = "revive"/'
	expect witness:EndedFinal -e 's/^    EndedFinal$/    W_EndedFinal/'
	model=CallCredit
	# The code before lane CALLCREDIT: no per-call credit, the receive loop
	# waits on a full call buffer (handoff.Stall).
	expect CC:no-credit -e 's/Mutant = "none"/Mutant = "no-credit"/' -e '/Conservation/d' -e '/GrantBound/d'
	expect CC:no-credit-live -e 's/Mutant = "none"/Mutant = "no-credit"/' -e '/Conservation/d' -e '/GrantBound/d' -e '/NoHOL/d'
	expect CC:no-return -e 's/Mutant = "none"/Mutant = "no-return"/' -e '/Conservation/d'
	expect CC:shared-buffer -e 's/Mutant = "none"/Mutant = "shared-buffer"/'
	# The relay before lane CALLCREDIT: a call's frames after its request EOM dropped.
	expect CC:drop-after-eom -e 's/Mutant = "none"/Mutant = "drop-after-eom"/' -e '/Conservation/d'
	expect witness:StuckFullHealthyDone -e 's/^    NoHOL$/    W_StuckFullHealthyDone/'
	expect witness:RelayPipeFull -e 's/^    NoHOL$/    W_RelayPipeFull/'
	expect witness:LateGrant -e 's/^    NoHOL$/    W_LateGrant/'
	expect witness:SenderWaits -e 's/^    NoHOL$/    W_SenderWaits/'
	expect witness:CancelDrop -e 's/^    NoHOL$/    W_CancelDrop/'
	model=CallCreditBoth
	# One direction uncredited (lane CALLCREDIT2: symmetry checked, not
	# assumed): its receive loop waits, and so does the other direction's
	# window updates behind it on the same connection.
	expect CCB:no-credit-req -e 's/Mutant = "none"/Mutant = "no-credit-req"/' -e '/Conservation/d' -e '/GrantBound/d'
	expect CCB:no-credit-req-holds-resp -e 's/Mutant = "none"/Mutant = "no-credit-req"/' -e '/Conservation/d' -e '/GrantBound/d' -e '/NoHOL/d' -e 's/^    HealthyDone$/    HealthyRespDone/'
	expect CCB:no-credit-resp -e 's/Mutant = "none"/Mutant = "no-credit-resp"/' -e '/Conservation/d' -e '/GrantBound/d'
	expect CCB:no-credit-resp-holds-req -e 's/Mutant = "none"/Mutant = "no-credit-resp"/' -e '/Conservation/d' -e '/GrantBound/d' -e '/NoHOL/d' -e 's/^    HealthyDone$/    HealthyReqDone/'
	expect CCB:drop-after-eom -e 's/Mutant = "none"/Mutant = "drop-after-eom"/' -e '/Conservation/d'
	expect witness:BothFullHealthyDone -e 's/^    NoHOL$/    W_BothFullHealthyDone/'
	expect witness:GrantBehindData -e 's/^    NoHOL$/    W_GrantBehindData/'
	expect witness:ReadWaits -e 's/^    NoHOL$/    W_ReadWaits/'
	expect witness:BothLateGrant -e 's/^    NoHOL$/    W_LateGrant/'
	model=CallCreditSenders
	# The code before lane FLAKECC: a call's concurrent senders each wait on
	# link.Credit's one wake token; one grant wakes one of them.
	expect CCS:no-lock -e 's/Mutant = "none"/Mutant = "no-lock"/'
	expect CCS:no-lock-live -e 's/Mutant = "none"/Mutant = "no-lock"/' -e '/NoStrandedWaiter/d'
	expect witness:BothWant -e 's/^    NoStrandedWaiter$/    W_BothWant/'
	expect witness:GrantToWaiter -e 's/^    NoStrandedWaiter$/    W_GrantToWaiter/'
	exit $fail
	;;
cctraces)
	# CallCredit traces recorded elsewhere (relay-core's two-agent tests:
	# its scripts/spec.sh traces runs this from the required relay version).
	shift
	[ $# -gt 0 ] || { echo "usage: spec.sh cctraces FILE..." >&2; exit 2; }
	for f in "$@"; do
		cp "$f" "$work/"
		cctraces "$work/$(basename "$f")" || fail=1
	done
	exit $fail
	;;
traces)
	# Every step TraceCallCredit.tla takes is one rpcclient records.
	ccgo=$(cat client/rpcclient/*.go | grep -v '^//' | grep -ohE 'traceCC\([a-z.]+, "[A-Za-z]+"' | grep -ohE '"[A-Za-z]+"' | sort -u)
	for e in $(grep -E 'E\.ev = ' spec/TraceCallCredit.tla | grep -ohE '"[A-Z][A-Za-z]*"' | sort -u); do
		echo "$ccgo" | grep -qx "$e" || { echo "spec/TraceCallCredit.tla: event $e is recorded by no traceCC in client/rpcclient"; exit 1; }
	done
	for f in spec/testdata/reject-callcredit-*.ndjson; do
		cp "$f" "$work/"
		if cctraces "$work/$(basename "$f")" >"$work/cc.out"; then
			echo "$f: accepted, want rejected"
			exit 1
		fi
		for o in "$work/$(basename "$f")".*.out; do
			grep -q 'distinct states found' "$o" || { echo "$f: TLC failed:"; tail -20 "$o"; exit 1; }
		done
		echo "$f: rejected"
	done
	for f in spec/testdata/reject-*.ndjson; do
		case $f in *reject-callcredit-*) continue ;; esac
		cp "$f" "$work/"
		if trace "$work/$(basename "$f")" 1 2; then
			echo "$f: accepted, want rejected"
			exit 1
		elif ! grep -q 'distinct states found' "$work/$(basename "$f").1.out"; then
			echo "$f: TLC failed:"
			tail -20 "$work/$(basename "$f").1.out"
			exit 1
		fi
		echo "$f: rejected"
	done
	for f in spec/testdata/accept-*.ndjson; do
		cp "$f" "$work/"
		trace "$work/$(basename "$f")" 1 2 || {
			echo "$f: rejected, want accepted"
			grep -E 'Error' "$work/$(basename "$f").1.out" | head -5
			exit 1
		}
		echo "$f: accepted"
	done
	mkdir -p "$work/traces"
	tests=${TRACE_TESTS:-'^(TestSignalConnSwitchLosesNothing|TestSignalConnJoiningPathCarriesEarlierFrames)$'}
	(cd client && RELAYTRACE=$work/traces go test -tags relaytrace -count=1 -run "$tests" ./p2p/) >"$work/test.out" 2>&1 || {
		cat "$work/test.out"
		exit 1
	}
	n=0 bad=0
	for t in "$work"/traces/*.ndjson; do
		for w in 1 2; do
			grep -q "\"op\":\"write\".*\"sc\":$w[,}]" "$t" || continue
			n=$((n + 1))
			if trace "$t" "$w" $((3 - w)); then
				echo "trace $(basename "$t") $w->$((3 - w)): $(wc -l <"$t" | tr -d ' ') lines: accepted"
			else
				bad=$((bad + 1))
				echo "trace $(basename "$t") $w->$((3 - w)): REJECTED"
				grep -E 'Error' "$t.$w.out" | head -5
			fi
		done
	done
	echo "$n traces, $bad rejected"
	[ "$n" -gt 0 ] && [ "$bad" = 0 ]
	;;
*)
	echo "usage: spec.sh check|mutants|traces|cctraces FILE..." >&2
	exit 2
	;;
esac
