#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# spec.sh check|mutants: the TLA+ models of spec/ (spec/README.md).
#   check    TLC on spec/SignalConn.cfg, spec/A2ASession.cfg, spec/CallCredit.cfg,
#            spec/CallCreditBoth.cfg, spec/CallCreditSenders.cfg,
#            spec/UDPFlow.cfg, spec/UDPFlowLive.cfg and spec/DatagramAssoc*.cfg:
#            their invariants and liveness
#            (LARGE=1 adds CallCreditLarge.cfg, CallCreditBothLarge.cfg,
#            UDPFlowLarge.cfg).
#   mutants  each bug put back must be caught.
#   traces   client/p2p's SignalConn tests (TRACE_TESTS) run with -tags
#            relaytrace; each trace, per direction that wrote, checked
#            against spec/TraceSignalConn.tla; each spec/testdata/reject-*
#            fixture rejected, each accept-* fixture accepted; every event
#            TraceCallCredit.tla takes recorded by client/rpcclient.
#   cltraces  the CallLifecycle traces of CL_TRACE_TESTS (default: the
#            stuck-handler test), CL_TRACE_COUNT runs (default 3), checked
#            against spec/TraceCallLifecycle.tla (in make ci).
#   cltraces FILE...  each transaction of each recorded CallLifecycle trace
#            checked against spec/TraceCallLifecycle.tla (relay-core's
#            two-agent traces: one config, this script's).
#   cctraces FILE...  each call and direction of each recorded CallCredit
#            trace (client/rpcclient -tags relaytrace) checked against
#            spec/TraceCallCredit.tla.
#   astraces  client/rpcclient's A2A E2EE session tests (AS_TRACE_TESTS,
#            default the retry, restart, forged-unknown, warm, revoke and
#            rotation ones; traces runs every TestA2AE2EE), each in its own
#            process with -tags relaytrace; each caller and callee pair of
#            each trace checked against spec/TraceA2ASession.tla; each
#            spec/testdata/reject-a2asession-* fixture rejected (in make ci).
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
    NoSilentLoss
    EndedFinal
    ReadBound
    PathOrdered
    TraceNotDone
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
    TypeOK
    NoHOL
    BufferBound
    Conservation
    GrantBound
    Ordered
    TraceNotDone
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

cltrace() {
	cfg=$work/$(basename "$1").$2.$3.cfg
	m=none
	grep "\"a\":\"$2\",\"c\":\"$3\"" "$1" | grep -q '"cont":true' || m=old-caller
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Agent = "$2"
    Call = "$3"
    Txns <- TraceTxns
    N <- TraceLen
    Retries <- TraceRetries
    Mutant = "$m"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    AtMostOneCall
    NoEndedEntry
    TraceNotDone
CFG
	META=$work/states-$(basename "$1").$2.$3 tlc "$cfg" TraceCallLifecycle.tla >"$1.$2.$3.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.$2.$3.out"
}

cltraces() {
	n=0 bad=0
	for ac in $(sed -E 's/.*"a":"([^"]+)","c":"([^"]+)".*/\1:\2/' "$1" | sort -u); do
		ag=${ac%%:*} call=${ac#*:}
		n=$((n + 1))
		if cltrace "$1" "$ag" "$call"; then
			echo "trace $(basename "$1") $ag $call: $(grep -c "\"a\":\"$ag\",\"c\":\"$call\"" "$1") lines: accepted"
		else
			bad=$((bad + 1))
			echo "trace $(basename "$1") $ag $call: REJECTED"
			grep -E 'Error|unknown event' "$1.$ag.$call.out" | head -5
			[ -z "${TRACE_KEEP:-}" ] || cp "$1" "$1.$ag.$call.out" "$TRACE_KEEP/"
		fi
	done
	echo "$n transactions, $bad rejected"
	[ "$n" -gt 0 ] && [ "$bad" = 0 ]
}

# clrun TESTS COUNT: client/rpcclient's tests TESTS (-count COUNT) with the
# recorder; every transaction of their CallLifecycle traces checked.
clrun() {
	mkdir -p "$work/cltraces"
	# CL_TRACE_SKIP: tests whose hostile relay loses a call's first frame
	# (T1), or the answers of a callee that restarts (L1): CallLifecycle.tla's
	# network loses nothing (the relay delivers in order), so their traces
	# are outside the model; what they check is spec/proverif/a2a_machine.pv's
	# (queries 16-18), A2ASession.tla's (astraces) and their own asserts.
	(cd client && RELAYTRACE=$work/cltraces go test -tags relaytrace -count="$2" -run "$1" \
		-skip "${CL_TRACE_SKIP:-^(TestA2AE2EERefusesDroppedFrame|TestA2AE2EELateResumeAfterRetryRefused|TestA2AE2EERestartAfterServeRefusesForgedRetry)$}" ./rpcclient/) >"$work/cltest.out" 2>&1 || {
		cat "$work/cltest.out"
		exit 1
	}
	for t in "$work"/cltraces/calllifecycle-*.ndjson; do
		cltraces "$t" || exit 1
	done
}

# astrace FILE CALLER CALLEE: TLC on one pair of a recorded A2ASession
# trace (spec/TraceA2ASession.tla); 0 when accepted. Its TLC output:
# FILE.CALLER.CALLEE.out. The window is rpcclient's a2aReplayWindow.
astrace() {
	cfg=$work/$(basename "$1").$2.$3.cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Caller = "$2"
    Callee = "$3"
    Calls <- TraceCalls
    MaxSess <- TraceSess
    W = 256
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    AtMostOnce
    NoKeyReuse
    OnceRetry
    TraceNotDone
CFG
	META=$work/states-$(basename "$1").$2.$3 tlc "$cfg" TraceA2ASession.tla >"$1.$2.$3.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.$2.$3.out"
}

# astraces FILE: each pair of an A2ASession trace; prints one line each,
# fails on a rejected one or none.
astraces() {
	n=0 bad=0
	for p in $(grep -v '"f":""' "$1" | sed -E 's/.*"f":"([^"]+)","t":"([^"]+)".*/\1>\2/' | sort -u); do
		fr=${p%%>*} to=${p#*>}
		n=$((n + 1))
		if astrace "$1" "$fr" "$to"; then
			echo "trace $(basename "$1") $fr>$to: $(grep -c "\"f\":\"$fr\",\"t\":\"$to\"" "$1") lines: accepted"
		else
			bad=$((bad + 1))
			echo "trace $(basename "$1") $fr>$to: REJECTED"
			grep -E 'Error|unknown event' "$1.$fr.$to.out" | head -5
		fi
	done
	echo "$n pairs, $bad rejected"
	[ "$n" -gt 0 ] && [ "$bad" = 0 ]
}

# asrun TESTS: the fixtures, then client/rpcclient's tests TESTS, each in
# its own process (they name their agents alike) with the recorder; every
# pair of their A2ASession traces checked. AS_TRACE_SKIP: the tests that
# make a session by hand (TestA2AE2EEv2Vectors: a resume on a session no
# handshake made), outside A2ASession.tla's runs.
asrun() {
	# Every event TraceA2ASession.tla takes is one rpcclient records.
	asgo=$(grep -hE 'traceAS\(|ev(, txn)? :?= "' client/rpcclient/*.go | grep -ohE '"[A-Z][A-Za-z]+"' | sort -u)
	for e in $(grep -E 'E\.ev = ' spec/TraceA2ASession.tla | grep -ohE '"[A-Z][A-Za-z]*"' | sort -u); do
		echo "$asgo" | grep -qx "$e" || { echo "spec/TraceA2ASession.tla: event $e is recorded by no traceAS in client/rpcclient"; return 1; }
	done
	for f in spec/testdata/reject-a2asession-*.ndjson; do
		cp "$f" "$work/"
		if astraces "$work/$(basename "$f")" >"$work/as.out"; then
			echo "$f: accepted, want rejected"
			return 1
		fi
		for o in "$work/$(basename "$f")".*.out; do
			grep -q 'distinct states found' "$o" || { echo "$f: TLC failed:"; tail -20 "$o"; return 1; }
		done
		echo "$f: rejected"
	done
	# One process per test: the tests name their agents alike.
	(cd client && go test -c -tags relaytrace -o "$work/rpcclient.test" ./rpcclient/) || return 1
	nt=0
	for t in $("$work/rpcclient.test" -test.list "$1"); do
		echo "$t" | grep -qE "${AS_TRACE_SKIP:-^TestA2AE2EEv2Vectors\$}" && continue
		mkdir -p "$work/astraces/$t"
		(cd client/rpcclient && RELAYTRACE=$work/astraces/$t "$work/rpcclient.test" -test.run "^$t\$" -test.count 1) >"$work/astest.out" 2>&1 || {
			cat "$work/astest.out"
			return 1
		}
		for f in "$work/astraces/$t"/a2asession-*.ndjson; do
			[ -s "$f" ] || continue
			mv "$f" "$work/astraces/$t.ndjson"
			nt=$((nt + 1))
			astraces "$work/astraces/$t.ndjson" || fail=1
		done
	done
	echo "$nt tests traced"
	[ "$nt" -gt 0 ] || fail=1
	return $fail
}

fail=0
cfg=
case ${1:-} in
check)
	cfgs="SignalConn CallCredit CallCreditBoth CallCreditSenders CallLifecycle CallLifecycleRetry A2ASession UDPFlow UDPFlowLive DatagramAssoc DatagramAssocTwo DatagramAssocMove DatagramAssocLive"
	[ -z "${LARGE:-}" ] || cfgs="$cfgs CallCreditLarge CallCreditBothLarge UDPFlowLarge"
	for c in $cfgs; do
		m=${c%Large}
		m=${m%Retry}
		m=${m%Live}
		m=${m%Two}
		m=${m%Move}
		echo "== $c.cfg"
		st=0
		tlc $c.cfg $m.tla >"$work/out" 2>&1 || st=$?
		grep -E '^[0-9]+ states generated|depth of|Error|violated' "$work/out" || true
		[ -z "${COVERAGE:-}" ] || grep -E '^<[A-Za-z]+.*>: 0:0$' "$work/out" | sed 's/^/never taken: /' || true
		[ $st = 0 ] || { tail -60 "$work/out"; exit $st; }
	done
	;;
mutants)
	# expect NAME SED...: $model.cfg (or $cfg.cfg) edited must violate a property.
	model=SignalConn
	expect() {
		name=$1
		shift
		sed "$@" spec/${cfg:-$model}.cfg >"$work/Mutant.cfg"
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
	# The code before lane FLAKECC (link before v0.12.3, no lock): a call's
	# concurrent senders each wait on link.Credit's one wake token; one
	# grant wakes one of them.
	expect CCS:one-slot -e 's/Mutant = "none"/Mutant = "one-slot"/'
	expect CCS:one-slot-live -e 's/Mutant = "none"/Mutant = "one-slot"/' -e '/NoStrandedWaiter/d'
	expect witness:BothWant -e 's/^    NoStrandedWaiter$/    W_BothWant/'
	expect witness:GrantToWaiter -e 's/^    NoStrandedWaiter$/    W_GrantToWaiter/'
	expect witness:WakeAll -e 's/^    NoStrandedWaiter$/    W_WakeAll/'
	model=CallLifecycle
	expect CL:late-new-call -e 's/Mutant = "none"/Mutant = "late-new-call"/'
	expect CL:old-caller -e 's/Mutant = "none"/Mutant = "old-caller"/'
	expect CL:tombstone -e 's/Mutant = "none"/Mutant = "tombstone"/'
	expect CL:refused-first-kept -e 's/Mutant = "none"/Mutant = "refused-first-kept"/'
	expect CL:drop-unknown -e 's/Mutant = "none"/Mutant = "drop-unknown"/' -e '/CancelKnown/d'
	# The code before lane A2AFINAL: a call refused at its caller (a revoked
	# key) sent its cancel though no frame of it went.
	expect CL:cancel-unreached -e 's/Mutant = "none"/Mutant = "cancel-unreached"/'
	expect witness:LateFrame -e 's/^    NoEndedEntry$/    W_LateFrame/'
	expect witness:LateData -e 's/^    NoEndedEntry$/    W_LateData/'
	expect witness:BothRun -e 's/^    NoEndedEntry$/    W_BothRun/'
	cfg=CallLifecycleRetry
	expect CL:retry-runs-again -e 's/Mutant = "none"/Mutant = "retry-runs-again"/'
	cfg=
	model=A2ASession
	expect AS:counter-reset -e 's/Mutant = "none"/Mutant = "counter-reset"/'
	expect AS:no-window -e 's/Mutant = "none"/Mutant = "no-window"/'
	expect AS:restart-keeps-sessions -e 's/Mutant = "none"/Mutant = "restart-keeps-sessions"/'
	expect AS:survive-revoke -e 's/Mutant = "none"/Mutant = "survive-revoke"/'
	expect AS:retry-loop -e 's/Mutant = "none"/Mutant = "retry-loop"/'
	expect witness:Resumed -e 's/^    AtMostOnce$/    W_Resumed/'
	expect witness:Rehandshake -e 's/^    AtMostOnce$/    W_Rehandshake/'
	expect witness:Failed -e 's/^    AtMostOnce$/    W_Failed/'
	expect AS:no-retry-check -e 's/Mutant = "none"/Mutant = "no-retry-check"/'
	expect AS:no-retry-bound -e 's/Mutant = "none"/Mutant = "no-retry-bound"/'
	expect AS:retry-no-take -e 's/Mutant = "none"/Mutant = "retry-no-take"/'
	expect witness:ForgedRefused -e 's/^    AtMostOnce$/    W_ForgedRefused/'
	expect witness:Lost -e 's/^    AtMostOnce$/    W_Lost/'
	# The code before lane A2AL1 (limit L1): the record in memory, lost on
	# a restart; and the record's write order and retention put wrong.
	expect AS:record-in-memory -e 's/Mutant = "none"/Mutant = "record-in-memory"/'
	expect AS:record-after-serve -e 's/Mutant = "none"/Mutant = "record-after-serve"/'
	expect AS:short-retention -e 's/Mutant = "none"/Mutant = "short-retention"/'
	expect witness:RestartRefused -e 's/^    AtMostOnce$/    W_RestartRefused/'
	model=UDPFlow
	# UDP tunnels (design, lane UDPTUN): each failure the flow lifecycle
	# prevents, put in.
	expect UDP:deliver-after-close -e 's/Mutant = "none"/Mutant = "deliver-after-close"/'
	expect UDP:no-client-cap -e 's/Mutant = "none"/Mutant = "no-client-cap"/'
	expect UDP:no-agent-cap -e 's/Mutant = "none"/Mutant = "no-agent-cap"/'
	expect UDP:grow-queue -e 's/Mutant = "none"/Mutant = "grow-queue"/'
	expect UDP:block-on-full -e 's/Mutant = "none"/Mutant = "block-on-full"/'
	expect witness:Refused -e 's/^    NoHOL$/    W_Refused/'
	expect witness:DropFull -e 's/^    NoHOL$/    W_DropFull/'
	expect witness:LateReply -e 's/^    NoHOL$/    W_LateReply/'
	expect witness:LateDatagram -e 's/^    NoHOL$/    W_LateDatagram/'
	expect witness:Expired -e 's/^    NoHOL$/    W_Expired/'
	expect witness:Reply -e 's/^    NoHOL$/    W_Reply/'
	expect witness:CutRecovered -e 's/^    NoHOL$/    W_CutRecovered/'
	cfg=UDPFlowLive
	expect UDP:no-idle -e 's/Mutant = "none"/Mutant = "no-idle"/'
	expect UDP:agent-only-close -e 's/Mutant = "none"/Mutant = "agent-only-close"/'
	cfg=
	model=DatagramAssoc
	# Datagram sessions between identities (design, lane NF1UDP): each
	# failure the association's flow lifecycle prevents, put in.
	expect DA:deliver-after-close -e 's/Mutant = "none"/Mutant = "deliver-after-close"/'
	expect DA:direct-ignores-assoc -e 's/Mutant = "none"/Mutant = "direct-ignores-assoc"/'
	expect DA:grow-queue -e 's/Mutant = "none"/Mutant = "grow-queue"/'
	expect DA:block-on-credit -e 's/Mutant = "none"/Mutant = "block-on-credit"/'
	expect DA:no-source-check -e 's/Mutant = "none"/Mutant = "no-source-check"/'
	expect DA:no-amp-cap -e 's/Mutant = "none"/Mutant = "no-amp-cap"/'
	expect DA:per-flow-budget -e 's/Mutant = "none"/Mutant = "per-flow-budget"/'
	expect witness:DA-Revoked -e 's/^    NoHOL$/    W_Revoked/'
	expect witness:DA-Refused -e 's/^    NoHOL$/    W_Refused/'
	expect witness:DA-AmpDrop -e 's/^    NoHOL$/    W_AmpDrop/'
	expect witness:DA-Reply -e 's/^    NoHOL$/    W_Reply/'
	cfg=DatagramAssocMove
	expect DA:tag-unchecked -e 's/Mutant = "none"/Mutant = "tag-unchecked"/'
	expect witness:DA-Direct -e 's/^    NoHOL$/    W_Direct/'
	expect witness:DA-Moved -e 's/^    NoHOL$/    W_Moved/'
	expect witness:DA-StaleTag -e 's/^    NoHOL$/    W_StaleTag/'
	cfg=DatagramAssocTwo
	# A reused id breaks ClosedFinal (an action property) first; with it
	# taken out the same trace reaches NoCrossFlow.
	expect DA:reuse-id -e 's/Mutant = "none"/Mutant = "reuse-id"/' -e '/^PROPERTIES$/d' -e '/ClosedFinal/d'
	expect DA:no-agent-cap -e 's/Mutant = "none"/Mutant = "no-agent-cap"/'
	expect DA:no-client-cap -e 's/Mutant = "none"/Mutant = "no-client-cap"/' -e 's/MaxFlowsC = 2/MaxFlowsC = 1/'
	expect witness:DA-FlowRefused -e 's/^    NoHOL$/    W_FlowRefused/'
	cfg=DatagramAssocLive
	expect DA:no-idle -e 's/Mutant = "none"/Mutant = "no-idle"/'
	cfg=
	exit $fail
	;;
cltraces)
	shift
	if [ $# -gt 0 ]; then
		for f in "$@"; do
			cp "$f" "$work/"
			cltraces "$work/$(basename "$f")" || fail=1
		done
		exit $fail
	fi
	# The per-push slice of traces: the CallLifecycle traces of the tests
	# whose handler returns before its caller's last frame
	# (CL_TRACE_TESTS), several runs, so AtMostOneCall is checked where a
	# late frame reaches the target.
	clrun "${CL_TRACE_TESTS:-^TestStuckHandlerDoesNotHoldTheReceiveLoop$}" "${CL_TRACE_COUNT:-3}"
	;;
astraces)
	# The per-push slice: the session tests of the retry, the restart, the
	# forged unknown, the warm, the revoke, the rotation and the restart
	# after a served call (L1).
	asrun "${AS_TRACE_TESTS:-^TestA2AE2EE(SessionReused|ResponderRestartRehandshakes|ForgedUnknownEndsCall|LateResumeAfterRetryRefused|RevokeEndsSession|RotationRekeys|RotationDoesNotRetryAServedCall|WarmLeavesASessionAndNoCall|RestartAfterServeRefusesForgedRetry)\$}" || fail=1
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
	for f in spec/testdata/accept-callcredit-*.ndjson; do
		cp "$f" "$work/"
		cctraces "$work/$(basename "$f")" >"$work/cc.out" || {
			echo "$f: rejected, want accepted"
			cat "$work/cc.out"
			exit 1
		}
		echo "$f: accepted"
	done
	clgo=$(cat client/rpcclient/*.go | grep -v '^//' | grep -ohE '"(Serve|Start|Drop|Refuse|Return)"' | sort -u)
	for e in $(grep -E 'E\.ev = ' spec/TraceCallLifecycle.tla | grep -ohE '"[A-Z][A-Za-z]*"' | sort -u); do
		echo "$clgo" | grep -qx "$e" || { echo "spec/TraceCallLifecycle.tla: event $e is recorded by no step of client/rpcclient"; exit 1; }
	done
	for f in spec/testdata/reject-calllifecycle-*.ndjson; do
		cp "$f" "$work/"
		if cltraces "$work/$(basename "$f")" >"$work/cl.out"; then
			echo "$f: accepted, want rejected"
			exit 1
		fi
		for o in "$work/$(basename "$f")".*.out; do
			grep -q 'distinct states found' "$o" || { echo "$f: TLC failed:"; tail -20 "$o"; exit 1; }
		done
		echo "$f: rejected"
	done
	clrun "${CL_TRACE_TESTS:-.}" 1
	asrun "${AS_TRACE_TESTS:-^TestA2AE2EE}" || exit 1
	for f in spec/testdata/reject-*.ndjson; do
		case $f in *reject-callcredit-* | *reject-calllifecycle-*) continue ;; esac
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
		case $f in *accept-callcredit-*) continue ;; esac
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
	echo "usage: spec.sh check|mutants|traces|cltraces|astraces|cctraces FILE..." >&2
	exit 2
	;;
esac
