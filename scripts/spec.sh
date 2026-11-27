#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# spec.sh check|mutants: the TLA+ models of spec/ (spec/README.md).
#   check    TLC on spec/A2ASession.cfg, spec/CallCredit.cfg,
#            spec/CallCreditBoth.cfg, spec/CallCreditSenders.cfg,
#            spec/UDPFlow.cfg, spec/UDPFlowLive.cfg, spec/DatagramAssoc*.cfg,
#            spec/BrowserPeer.cfg, spec/DirectPunch.cfg, spec/PunchRound*.cfg,
#            spec/AgentStop*.cfg and
#            spec/TLSEnd.cfg, spec/AuditLog*.cfg, spec/MoveAudit.cfg:
#            their invariants and liveness
#            (LARGE=1 adds CallCreditLarge.cfg, CallCreditBothLarge.cfg,
#            UDPFlowLarge.cfg).
#   mutants  each bug put back must be caught.
#   traces   every trace check below with its fixtures; every event
#            TraceCallCredit.tla takes recorded by client/rpcclient.
#   cltraces  the CallLifecycle traces of CL_TRACE_TESTS (default: the
#            stuck-handler test), CL_TRACE_COUNT runs (default 3), checked
#            against spec/TraceCallLifecycle.tla (in make ci).
#   cltraces FILE...  each transaction of each recorded CallLifecycle trace
#            checked against spec/TraceCallLifecycle.tla (relay-core's
#            two-agent traces: one config, this script's).
#   ccruns    client/rpcclient's CallCredit tests (CC_TRACE_TESTS, default
#            CCTESTS: the two-agent bridge and concurrent-sender tests), each
#            in its own process with -tags relaytrace; each call checked per
#            direction (TraceCallCredit.tla), both ways
#            (TraceCallCreditBoth.tla) and, sent from several goroutines,
#            per sender (TraceCallCreditSenders.tla); each
#            spec/testdata/reject-callcreditboth-*/-senders-* rejected
#            (traces runs it too).
#   cctraces FILE...  each call and direction of each recorded CallCredit
#            trace (client/rpcclient -tags relaytrace) checked against
#            spec/TraceCallCredit.tla.
#   dgtraces  client/dgram's traced association tests (DG_TRACE_TESTS,
#            default TestDatagramAssocTrace and TestDatagramAssocTraceRevoke,
#            DG_TRACE_COUNT runs, default 3)
#            and client/agent's that move direct (DG_DIRECT_TESTS),
#            each run in its own process with -tags relaytrace, its trace
#            checked against spec/TraceDatagramAssoc.tla; each
#            spec/testdata/reject-datagramassoc-* fixture rejected (in make
#            ci; traces runs it too).
#   ptraces   client/agent's punch tests (P_TRACE_TESTS), each in its own
#            process with -tags relaytrace, every punch's trace checked
#            against spec/TraceDirectPunch.tla; each
#            spec/testdata/reject-directpunch-* fixture rejected (in make
#            ci; traces runs it too).
#   bptraces  client/p2p's browser direct path tests (BP_TRACE_TESTS,
#            default a two-stream session and a visitor closing its
#            connection; traces runs every TestBrowserDirect and the
#            bindings rows), with -tags relaytrace; each control session's
#            trace checked against spec/TraceBrowserPeer.tla; each
#            spec/testdata/reject-browserpeer-* fixture rejected (in make ci).
#   astraces  client/rpcclient's A2A E2EE session tests (AS_TRACE_TESTS,
#            default the retry, restart, forged-unknown, warm, revoke and
#            rotation ones; traces runs every TestA2AE2EE), each in its own
#            process with -tags relaytrace; each caller and callee pair of
#            each trace checked against spec/TraceA2ASession.tla; each
#            spec/testdata/reject-a2asession-* fixture rejected (in make ci).
#   audittraces  client/orgaudit's and org/orgenrol's audit tests, each in
#            its own process with -tags audittrace; each machine
#            directory's log trace checked against spec/TraceAuditLog.tla,
#            each process's move trace against spec/TraceMoveAudit.tla;
#            each spec/testdata/{accept,reject}-{auditlog,moveaudit}-*
#            fixture accepted or rejected (nightly: traces runs it).
#   stoptraces  client/agent's SENDCUT stop tests (STOP_TRACE_TESTS) in one
#            process with -tags relaytrace; each directServer's trace
#            checked against spec/TraceAgentStop.tla (in make ci; traces
#            runs every stop test and rejects each
#            spec/testdata/reject-agentstop-* fixture).
# COVERAGE=1 adds -coverage 1. Java and tla2tools.jar come from
# scripts/fetch-tla.sh.
set -eu
cd "$(dirname "$0")/.."
tools=$(scripts/fetch-tla.sh)
java=$(echo "$tools" | sed -n 1p)
jar=$(echo "$tools" | sed -n 2p)
work=$(mktemp -d)
# TLC runs go through scripts/cicache.sh: kept only when this script passes.
cicache=$PWD/scripts/cicache.sh
[ -x "$cicache" ] || { echo "spec.sh: $cicache missing or not executable" >&2; exit 2; }
CICACHE_STAGE=$("$cicache" begin || true)
export CICACHE_STAGE
trap 'st=$?; "$cicache" end "$CICACHE_STAGE" $st || st=1; rm -rf "$work"; exit $st' EXIT
. "$PWD/scripts/pool.sh"

tlc() {
	c=$1 mod=$2
	shift 2
	cov=
	[ -z "${COVERAGE:-}" ] || cov="-coverage 1"
	(cd spec && "$cicache" tlc -- "$java" -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "${TLC_WORKERS:-2}" $cov \
		-deadlock -noGenerateSpecTE -metadir "${META:-$work/states}" -config "$c" "$@" "$mod")
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

# ccbtrace FILE C: TLC on call C of a recorded CallCredit trace, both
# directions at once (spec/TraceCallCreditBoth.tla); 0 when accepted. A
# call the caller left (Cancel) is one of Ends: its directions with no Read
# are stuck. Its TLC output: FILE.both.C.out.
ccbtrace() {
	sreq={} sresp={}
	if grep -q "\"ev\":\"Cancel\",\"d\":\"[a-z]*\",\"c\":\"$2\"" "$1"; then
		grep -q "\"ev\":\"Read\",\"d\":\"req\",\"c\":\"$2\"" "$1" || sreq="{\"$2\"}"
		grep -q "\"ev\":\"Read\",\"d\":\"resp\",\"c\":\"$2\"" "$1" || sresp="{\"$2\"}"
	fi
	cfg=$work/$(basename "$1").both.$2.cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Call = "$2"
    Calls <- TraceCalls
    StuckReq = $sreq
    StuckResp = $sresp
    WReq = 16
    WResp = 256
    N <- TraceLen
    NReq <- TraceNReq
    P = 1
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
	META=$work/states-$(basename "$1").both.$2 tlc "$cfg" TraceCallCreditBoth.tla >"$1.both.$2.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.both.$2.out"
}

# ccstrace FILE C: TLC on the responses of call C of a recorded CallCredit
# trace, sent from several goroutines (spec/TraceCallCreditSenders.tla); 0
# when accepted. Its TLC output: FILE.senders.C.out.
ccstrace() {
	starts=$(grep "\"ev\":\"Start\",\"d\":\"resp\",\"c\":\"$2\"" "$1" | sed -E 's/.*"s":([0-9]+).*/\1/' | sort | uniq -c)
	senders=$(echo "$starts" | awk '{print $2}' | paste -sd, -)
	m=$(echo "$starts" | awk '$1 > m {m = $1} END {print m}')
	cfg=$work/$(basename "$1").senders.$2.cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Call = "$2"
    Senders = {$senders}
    W = 256
    M = $m
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    Conservation
    NoStrandedWaiter
    TraceNotDone
CFG
	META=$work/states-$(basename "$1").senders.$2 tlc "$cfg" TraceCallCreditSenders.tla >"$1.senders.$2.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.senders.$2.out"
}

# ccbstraces FILE: each call of a CallCredit trace against
# TraceCallCreditBoth.tla, and each call whose responses two or more
# goroutines started against TraceCallCreditSenders.tla; prints one line
# each, fails on a rejected one or none.
ccbstraces() {
	n=0 bad=0
	for call in $(sed -E 's/.*"c":"([^"]+)".*/\1/' "$1" | sort -u); do
		# Both ways: a call whose caller is an agent of the run.
		if grep -q "\"ev\":\"Send\",\"d\":\"req\",\"c\":\"$call\"" "$1"; then
			n=$((n + 1))
			if ccbtrace "$1" "$call"; then
				echo "trace $(basename "$1") $call both: $(grep -c "\"c\":\"$call\"" "$1") lines: accepted"
			else
				bad=$((bad + 1))
				echo "trace $(basename "$1") $call both: REJECTED"
				grep -E 'Error|unknown event' "$1.both.$call.out" | head -5
			fi
		fi
		ns=$(grep "\"ev\":\"Start\",\"d\":\"resp\",\"c\":\"$call\"" "$1" | sed -E 's/.*"s":([0-9]+).*/\1/' | sort -u | wc -l | tr -d ' ')
		[ "$ns" -ge 2 ] || continue
		n=$((n + 1))
		if ccstrace "$1" "$call"; then
			echo "trace $(basename "$1") $call senders ($ns): accepted"
		else
			bad=$((bad + 1))
			echo "trace $(basename "$1") $call senders ($ns): REJECTED"
			grep -E 'Error|unknown event' "$1.senders.$call.out" | head -5
		fi
	done
	echo "$n checks, $bad rejected"
	[ "$n" -gt 0 ] && [ "$bad" = 0 ]
}

# ccrun TESTS: client/rpcclient's two-agent and concurrent-sender tests
# (TESTS, a -run pattern), each in its own process with -tags relaytrace;
# every call of each CallCredit trace checked per direction
# (TraceCallCredit.tla), both ways (TraceCallCreditBoth.tla) and, served
# from several goroutines, per sender (TraceCallCreditSenders.tla); each
# spec/testdata/reject-callcreditboth-* and reject-callcreditsenders-*
# fixture rejected.
ccrun() {
	fail=0
	for f in spec/testdata/reject-callcreditboth-*.ndjson spec/testdata/reject-callcreditsenders-*.ndjson; do
		cp "$f" "$work/"
		ccbstraces "$work/$(basename "$f")" >"$work/ccbs.out" || true
		# The machine the fixture is for is the one that rejects it.
		want="both: REJECTED"
		case $f in *senders-*) want="senders (.*): REJECTED" ;; esac
		grep -qE "$want" "$work/ccbs.out" || {
			echo "$f: accepted, want rejected"
			cat "$work/ccbs.out"
			return 1
		}
		for o in "$work/$(basename "$f")".*.out; do
			grep -q 'distinct states found' "$o" || { echo "$f: TLC failed:"; tail -20 "$o"; return 1; }
		done
		echo "$f: rejected"
	done
	(cd client && go test -c -tags relaytrace -o "$work/ccrpc.test" ./rpcclient/) || return 1
	nt=0
	for t in $("$work/ccrpc.test" -test.list "$1"); do
		mkdir -p "$work/cctraces/$t"
		(cd client/rpcclient && RELAYTRACE=$work/cctraces/$t "$work/ccrpc.test" -test.run "^$t\$" -test.count 1) >"$work/cctest.out" 2>&1 || {
			cat "$work/cctest.out"
			return 1
		}
		for f in "$work/cctraces/$t"/callcredit-*.ndjson; do
			[ -s "$f" ] || continue
			mv "$f" "$work/cctraces/$t.ndjson"
			nt=$((nt + 1))
			# A run with no caller agent (the test grants by hand) is
			# CallCreditSenders' only: CallCredit and CallCreditBoth
			# have the caller's steps.
			if grep -q '"ev":"Send","d":"req"' "$work/cctraces/$t.ndjson"; then
				cctraces "$work/cctraces/$t.ndjson" || fail=1
			fi
			ccbstraces "$work/cctraces/$t.ndjson" || fail=1
		done
	done
	echo "$nt tests traced"
	[ "$nt" -gt 0 ] || fail=1
	return $fail
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

# dgtrace FILE: TLC on a recorded DatagramAssoc trace
# (spec/TraceDatagramAssoc.tla); 0 when accepted. Its TLC output: FILE.out.
dgtrace() {
	cfg=$work/$(basename "$1").cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Srcs <- TraceSrcs
    Adm <- TraceAdm
    Busy <- TraceBusy
    N <- TraceLen
    Sends <- TraceSends
    Ids <- TraceIds
    MaxEp = 1
    MaxFlowsC <- TraceMaxFlowsC
    MaxFlows <- TraceMaxFlowsA
    W <- TraceLen
    Q <- TraceLen
    Amp <- TraceLen
    R = 1
    B <- TraceLen
    MaxCuts <- TraceLen
    MaxLoss <- TraceLen
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    NoDeliverAfterClose
    NoCrossFlow
    TableBounded
    NoHOL
    NoReflection
    NoLostOnMove
    NoDeliverAfterRevoke
    TraceNotDone
CFG
	META=$work/states-$(basename "$1") tlc "$cfg" TraceDatagramAssoc.tla >"$1.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.out"
}

# ptrace FILE: TLC on a recorded DirectPunch trace
# (spec/TraceDirectPunch.tla); 0 when accepted. Its TLC output: FILE.out.
ptrace() {
	cfg=$work/$(basename "$1").cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Offered <- TraceOffered
    Prflx <- TracePrflx
    Spoofed <- TraceSpoofed
    Trickled = {}
    Peer <- TracePeer
    Rogue <- TraceRogue
    Lan <- TraceLan
    Reach = {}
    MaxCands = 8
    Bound = 1
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    OnlyTagged
    DialBound
    OnlyPeer
    OneConnection
    DirectIfWorks
    PreferLan
    NoWait
    TraceNotDone
CFG
	META=$work/states-$(basename "$1") tlc "$cfg" TraceDirectPunch.tla >"$1.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.out"
}

# pmtrace FILE: TLC on a recorded PortMap trace (spec/TracePortMap.tla);
# 0 when accepted. Its TLC output: FILE.out.
pmtrace() {
	cfg=$work/$(basename "$1").cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    MaxRounds = 8
    MaxChanges = 3
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    NoPermanent
    OneLive
    NoMapAfterClose
    DeletedOnClose
    TraceNotDone
CFG
	META=$work/states-$(basename "$1") tlc "$cfg" TracePortMap.tla >"$1.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.out"
}

# prtrace FILE: TLC on a recorded PunchRound trace
# (spec/TracePunchRound.tla, PunchRound.cfg's constants); 0 when accepted.
# Its TLC output: FILE.out.
prtrace() {
	cfg=$work/$(basename "$1").cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Delays = {1, 3}
    Dd = 1
    PTO = 2
    PunchBound = 4
    CtlBound = 7
    MaxAttempts = 3
    Kind = "cone"
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    RetryBound
    RetryOnlyNoAnswer
    InitialAfterProbe
    NeverHeld
    DirectOnlyWon
    FirstInitialWins
    TraceNotDone
CFG
	META=$work/states-$(basename "$1") tlc "$cfg" TracePunchRound.tla >"$1.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.out"
}

# prun TESTS: the fixtures, then client/agent's tests TESTS, each in its
# own process with the recorder; every punch's trace checked.
prun() {
	pgo=$(grep -ohE '"ev": "[A-Za-z]+"|ev := "[A-Za-z]+"|ev = "[A-Za-z]+"' client/agent/trace_punch_on.go | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u)
	for e in $(grep -oE 'E\.ev = "[A-Za-z]+"' spec/TraceDirectPunch.tla | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u); do
		echo "$pgo" | grep -qx "$e" || { echo "spec/TraceDirectPunch.tla: event $e is recorded by no trace line of client/agent"; return 1; }
	done
	for f in spec/testdata/reject-directpunch-*.ndjson; do
		cp "$f" "$work/"
		if ptrace "$work/$(basename "$f")"; then
			echo "$f: accepted, want rejected"
			return 1
		fi
		grep -q 'distinct states found' "$work/$(basename "$f").out" || { echo "$f: TLC failed:"; tail -20 "$work/$(basename "$f").out"; return 1; }
		echo "$f: rejected"
	done
	prgo=$(grep -ohE '"ev": "[A-Za-z]+"|ev := "[A-Za-z]+"|ev = "[A-Za-z]+"' client/agent/trace_round_on.go | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u)
	for e in $(grep -oE 'E\.ev = "[A-Za-z]+"' spec/TracePunchRound.tla | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u); do
		echo "$prgo" | grep -qx "$e" || { echo "spec/TracePunchRound.tla: event $e is recorded by no trace line of client/agent"; return 1; }
	done
	for f in spec/testdata/reject-punchround-*.ndjson; do
		cp "$f" "$work/"
		if prtrace "$work/$(basename "$f")"; then
			echo "$f: accepted, want rejected"
			return 1
		fi
		grep -q 'distinct states found' "$work/$(basename "$f").out" || { echo "$f: TLC failed:"; tail -20 "$work/$(basename "$f").out"; return 1; }
		echo "$f: rejected"
	done
	pmgo=$(grep -ohE 'line\("[A-Za-z]+"' client/agent/direct_portmap.go | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u)
	for e in $(grep -oE 'E\.ev = "[A-Za-z]+"' spec/TracePortMap.tla | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u); do
		echo "$pmgo" | grep -qx "$e" || { echo "spec/TracePortMap.tla: event $e is recorded by no trace line of client/agent"; return 1; }
	done
	for f in spec/testdata/reject-portmap-*.ndjson; do
		cp "$f" "$work/"
		if pmtrace "$work/$(basename "$f")"; then
			echo "$f: accepted, want rejected"
			return 1
		fi
		grep -q 'distinct states found' "$work/$(basename "$f").out" || { echo "$f: TLC failed:"; tail -20 "$work/$(basename "$f").out"; return 1; }
		echo "$f: rejected"
	done
	(cd client && go test -c -tags relaytrace -o "$work/agent.test" ./agent/) || return 1
	nt=0
	nr=0
	nm=0
	for t in $("$work/agent.test" -test.list "$1"); do
		d=$work/ptraces/$t
		mkdir -p "$d"
		(cd client/agent && RELAYTRACE=$d "$work/agent.test" -test.run "^$t\$" -test.count 1) >"$work/ptest.out" 2>&1 || {
			cat "$work/ptest.out"
			return 1
		}
		for f in "$d"/directpunch-*.ndjson; do
			[ -s "$f" ] || continue
			nt=$((nt + 1))
			if ptrace "$f"; then
				echo "trace $t $(basename "$f"): $(wc -l <"$f" | tr -d ' ') lines: accepted"
			else
				echo "trace $t $(basename "$f"): REJECTED"
				grep -E 'Error|unknown event' "$f.out" | head -5
				fail=1
			fi
		done
		for f in "$d"/punchround-*.ndjson; do
			[ -s "$f" ] || continue
			nr=$((nr + 1))
			if prtrace "$f"; then
				echo "round trace $t $(basename "$f"): $(wc -l <"$f" | tr -d ' ') lines: accepted"
			else
				echo "round trace $t $(basename "$f"): REJECTED"
				grep -E 'Error|unknown event' "$f.out" | head -5
				fail=1
			fi
		done
		for f in "$d"/portmap-*.ndjson; do
			[ -s "$f" ] || continue
			nm=$((nm + 1))
			if pmtrace "$f"; then
				echo "portmap trace $t $(basename "$f"): $(wc -l <"$f" | tr -d ' ') lines: accepted"
			else
				echo "portmap trace $t $(basename "$f"): REJECTED"
				grep -E 'Error|unknown event' "$f.out" | head -5
				fail=1
			fi
		done
	done
	echo "$nt traces, $nr round traces, $nm portmap traces"
	[ "$nt" -gt 0 ] && [ "$nr" -gt 0 ] && [ "$nm" -gt 0 ] || fail=1
	return $fail
}

# dgrun TESTS COUNT [PKG]: the fixtures, then client/PKG's (default dgram;
# agent: the direct path's) tests TESTS, each run COUNT times in its own
# process (one association per trace) with the recorder; every trace
# checked.
dgrun() {
	pkg=${3:-dgram}
	dggo=$(grep -ohE 'ev":"[A-Za-z]+|"(Bind[AC]|RecvDg[AC])"' client/dgram/trace_on.go client/agent/direct_server.go client/agent/direct_client.go | sed 's/ev":"//' | tr -d '"' | sort -u)
	for e in $(grep -oE 'E\.ev = "[A-Za-z]+"' spec/TraceDatagramAssoc.tla | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u); do
		echo "$dggo" | grep -qx "$e" || { echo "spec/TraceDatagramAssoc.tla: event $e is recorded by no trace line of client/dgram"; return 1; }
	done
	for f in $([ "$pkg" = dgram ] && echo spec/testdata/reject-datagramassoc-*.ndjson); do
		cp "$f" "$work/"
		if dgtrace "$work/$(basename "$f")"; then
			echo "$f: accepted, want rejected"
			return 1
		fi
		grep -q 'distinct states found' "$work/$(basename "$f").out" || { echo "$f: TLC failed:"; tail -20 "$work/$(basename "$f").out"; return 1; }
		echo "$f: rejected"
	done
	(cd client && go test -c -tags relaytrace -o "$work/$pkg.dg.test" "./$pkg/") || return 1
	nt=0
	for t in $("$work/$pkg.dg.test" -test.list "$1"); do
		i=0
		while [ $i -lt "$2" ]; do
			i=$((i + 1))
			d=$work/dgtraces/$t.$i
			mkdir -p "$d"
			(cd "client/$pkg" && RELAYTRACE=$d "$work/$pkg.dg.test" -test.run "^$t\$" -test.count 1) >"$work/dgtest.out" 2>&1 || {
				cat "$work/dgtest.out"
				return 1
			}
			for f in "$d"/datagramassoc-*.ndjson; do
				[ -s "$f" ] || continue
				nt=$((nt + 1))
				if dgtrace "$f"; then
					echo "trace $t.$i: $(wc -l <"$f" | tr -d ' ') lines: accepted"
				else
					echo "trace $t.$i: REJECTED"
					grep -E 'Error|unknown event' "$f.out" | head -5
					fail=1
				fi
			done
		done
	done
	echo "$nt traces"
	[ "$nt" -gt 0 ] || fail=1
	return $fail
}

# bptrace FILE: TLC on a recorded BrowserPeer trace
# (spec/TraceBrowserPeer.tla); 0 when accepted. Its TLC output: FILE.out.
bptrace() {
	cfg=$work/$(basename "$1").cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    N <- TraceN
    MaxDC <- TraceMaxDC
    MaxFail <- TraceLen
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    AtMostOnce
    PCOnlyAdmitted
    DCOnPC
    DCBounded
    TraceNotDone
CFG
	META=$work/states-$(basename "$1") tlc "$cfg" TraceBrowserPeer.tla >"$1.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.out"
}

# bprun TESTS: the fixtures, then client/p2p's tests TESTS with the
# recorder; every control session's trace checked.
bprun() {
	bpgo=$(cat client/p2p/browserpeer.go | grep -v '^//' | grep -ohE '(emit|step)\("[A-Za-z]+"' | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u)
	for e in $(grep -oE 'E\.ev = "[A-Za-z]+"' spec/TraceBrowserPeer.tla | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u); do
		[ "$e" = Serve ] && continue
		echo "$bpgo" | grep -qx "$e" || { echo "spec/TraceBrowserPeer.tla: event $e is recorded by no step of client/p2p browserpeer.go"; return 1; }
	done
	for f in spec/testdata/reject-browserpeer-*.ndjson; do
		cp "$f" "$work/"
		if bptrace "$work/$(basename "$f")"; then
			echo "$f: accepted, want rejected"
			return 1
		fi
		grep -q 'distinct states found' "$work/$(basename "$f").out" || { echo "$f: TLC failed:"; tail -20 "$work/$(basename "$f").out"; return 1; }
		echo "$f: rejected"
	done
	mkdir -p "$work/bptraces"
	(cd client && RELAYTRACE=$work/bptraces go test -tags relaytrace -count=1 -run "$1" ./p2p/) >"$work/bptest.out" 2>&1 || {
		cat "$work/bptest.out"
		return 1
	}
	nt=0
	for f in "$work"/bptraces/browserpeer-*.ndjson; do
		[ -s "$f" ] || continue
		nt=$((nt + 1))
		if bptrace "$f"; then
			echo "trace $(basename "$f"): $(wc -l <"$f" | tr -d ' ') lines: accepted"
		else
			echo "trace $(basename "$f"): REJECTED"
			grep -E 'Error|unknown event' "$f.out" | head -5
			fail=1
		fi
	done
	echo "$nt traces"
	[ "$nt" -gt 0 ] || fail=1
	return $fail
}

# stoptrace FILE: TLC on a recorded AgentStop trace
# (spec/TraceAgentStop.tla); 0 when accepted. Its TLC output: FILE.out.
stoptrace() {
	cfg=$work/$(basename "$1").cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    c1 = c1
    Sessions <- TraceSessions
    Direct <- TraceSessions
    Late <- TraceSessions
    Closers = {c1}
    Drain = 0
    Grace = 1
    MaxBytes = 1
    MaxTime = 6
    Mutant = "none"
    CloseWaits = FALSE
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    NoSilentLoss
    NoEarlyReset
    ExitAfterEnd
    TraceNotDone
CFG
	META=$work/states-$(basename "$1") tlc "$cfg" TraceAgentStop.tla >"$1.out" 2>&1 || true
	grep -q '^Error: Invariant TraceNotDone is violated' "$1.out"
}

# stoprun TESTS [fixtures]: the fixtures (when asked), then client/agent's
# tests TESTS in one process with the recorder; every directServer's trace
# checked.
stoprun() {
	sgo=$(grep -ohE '"ev": "[A-Za-z]+"|ev\("[A-Za-z]+"\)' client/agent/trace_stop_on.go | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u)
	for e in $(grep -oE 'E\.ev = "[A-Za-z]+"' spec/TraceAgentStop.tla | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u); do
		echo "$sgo" | grep -qx "$e" || { echo "spec/TraceAgentStop.tla: event $e is recorded by no trace line of client/agent"; return 1; }
	done
	for f in spec/testdata/reject-agentstop-*.ndjson; do
		[ "${2:-}" = fixtures ] || break
		cp "$f" "$work/"
		if stoptrace "$work/$(basename "$f")"; then
			echo "$f: accepted, want rejected"
			return 1
		fi
		grep -q 'distinct states found' "$work/$(basename "$f").out" || { echo "$f: TLC failed:"; tail -20 "$work/$(basename "$f").out"; return 1; }
		echo "$f: rejected"
	done
	d=$work/stoptraces
	mkdir -p "$d"
	(cd client && RELAYTRACE=$d go test -tags relaytrace -count=1 -run "$1" ./agent/) >"$work/stest.out" 2>&1 || {
		cat "$work/stest.out"
		return 1
	}
	nt=0
	for f in "$d"/agentstop-*.ndjson; do
		[ -s "$f" ] || continue
		nt=$((nt + 1))
		if stoptrace "$f"; then
			echo "trace $(basename "$f"): $(wc -l <"$f" | tr -d ' ') lines: accepted"
		else
			echo "trace $(basename "$f"): REJECTED"
			grep -E 'Error|unknown event' "$f.out" | head -5
			fail=1
		fi
	done
	echo "$nt traces"
	[ "$nt" -gt 0 ] || fail=1
	return $fail
}

# tetrace FILE: TLC on one direction of a session's end under end-to-end
# TLS (spec/TraceTLSEnd.tla, lane ENDTRACE); 0 when TLC reaches the
# trace's end with Y's Close returned (TraceUnfinished violated).
tetrace() {
	cfg=$work/$(basename "$1").cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    NoFalseReset
    TraceUnfinished
CFG
	META=$work/states-$(basename "$1") tlc "$cfg" TraceTLSEnd.tla >"$1.out" 2>&1 || true
	grep -q '^Error: Invariant TraceUnfinished is violated' "$1.out"
}

# altrace FILE / mvtrace FILE: TLC on one recorded AuditLog trace (a
# machine directory's, spec/TraceAuditLog.tla) or MoveAudit trace (a test
# process's, spec/TraceMoveAudit.tla); 0 when accepted. Its TLC output:
# FILE.out.
altrace() {
	cfg=$work/$(basename "$1").cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    Procs <- TraceProcs
    MayCrash <- TraceProcs
    Sess <- TraceSess
    MaxRot <- TraceMaxRot
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    AtMostOneClose
    CloseHasOpen
    LiveOpenNotClosed
    NothingLost
    OneLog
    TraceUnfinished
CFG
	META=$work/states-$(basename "$1") tlc "$cfg" TraceAuditLog.tla >"$1.out" 2>&1 || true
	grep -q '^Error: Invariant TraceUnfinished is violated' "$1.out"
}
mvtrace() {
	cfg=$work/$(basename "$1").cfg
	cat >"$cfg" <<CFG
CONSTANTS
    TraceFile = "$1"
    NH <- TraceNH
    MaxLines <- TraceMaxLines
    Mutant = "none"
INIT TraceInit
NEXT TraceNext
INVARIANTS
    TypeOK
    AckedHeld
    NoGap
    TraceUnfinished
CFG
	META=$work/states-$(basename "$1") tlc "$cfg" TraceMoveAudit.tla >"$1.out" 2>&1 || true
	grep -q '^Error: Invariant TraceUnfinished is violated' "$1.out"
}

# auditrun: every event TraceAuditLog.tla and TraceMoveAudit.tla map is
# one the code records; the fixtures (accept-auditlog-*, reject-auditlog-*,
# accept-moveaudit-*, reject-moveaudit-*: each mutant's step) are
# accepted and rejected; then the audit tests (AUDIT_CLIENT_TESTS in
# client/orgaudit, AUDIT_ORG_TESTS in org/orgenrol), each in its own
# process with -tags audittrace (org: 'enroltrace audittrace'), every
# machine directory's trace and every process's move trace accepted.
# Not traced: tests that plant lines or owner files the recorder never
# saw (a crafted log, an edited line).
AUDIT_CLIENT_TESTS='TestKilledProcessSessionClosedLost TestKilledBetweenStepsClosedOnce TestAuditRotationKeepsTheLog'
AUDIT_ORG_TESTS='TestAuditReachesTheIssuer TestAuditFollowsTheMove TestAuditNotTakenAfterTheFence TestSDKOnlyMachineShipsItsAudit'
auditrun() {
	for m in AuditLog MoveAudit; do
		for e in $(grep -oE 'E\.ev = "[a-z]+"' "spec/Trace$m.tla" | grep -ohE '"[a-z]+"' | sort -u); do
			grep -rqF -- "$e" --include='*.go' client/orgaudit org/internal/audittrace org/orgenrol org/orgissuer || { echo "spec/Trace$m.tla: event $e is recorded nowhere"; return 1; }
		done
	done
	for f in spec/testdata/accept-auditlog-*.ndjson spec/testdata/reject-auditlog-*.ndjson spec/testdata/accept-moveaudit-*.ndjson spec/testdata/reject-moveaudit-*.ndjson; do
		cp "$f" "$work/"
		chk=altrace
		case $f in *moveaudit*) chk=mvtrace ;; esac
		want=accepted
		case $f in *reject-*) want=rejected ;; esac
		got=rejected
		! $chk "$work/$(basename "$f")" || got=accepted
		grep -q 'distinct states found' "$work/$(basename "$f").out" || { echo "$f: TLC failed:"; tail -20 "$work/$(basename "$f").out"; return 1; }
		[ $got = $want ] || { echo "$f: $got, want $want"; return 1; }
		echo "$f: $got"
	done
	nt=0 fail=0
	for mt in $(for t in $AUDIT_CLIENT_TESTS; do echo "client:$t"; done) $(for t in $AUDIT_ORG_TESTS; do echo "org:$t"; done); do
		mod=${mt%%:*} t=${mt#*:} d=$work/audittraces/$t
		mkdir -p "$d"
		pkg=./orgaudit/ tags=audittrace
		[ "$mod" = client ] || pkg=./orgenrol/ tags='enroltrace audittrace'
		(cd "$mod" && AUDITTRACE=$d go test -tags "$tags" -count=1 -run "^$t\$" "$pkg") >"$work/audittest.out" 2>&1 || {
			cat "$work/audittest.out"
			return 1
		}
		for f in "$d"/auditlog-*.ndjson "$d"/*.moveaudit; do
			[ -s "$f" ] || continue
			nt=$((nt + 1))
			chk=altrace
			case $f in *.moveaudit) chk=mvtrace ;; esac
			if $chk "$f"; then
				echo "trace $t/$(basename "$f"): $(wc -l <"$f" | tr -d ' ') lines: accepted"
			else
				echo "trace $t/$(basename "$f"): REJECTED"
				grep -E 'Error|unknown event' "$f.out" | head -5
				fail=1
			fi
		done
	done
	echo "$nt traces"
	[ "$nt" -gt 0 ] || fail=1
	return $fail
}

# terun TESTS: every event TraceTLSEnd.tla maps is one client/tlsend
# records; the fixtures (accept-tlsend-*, reject-tlsend-*: each mutant's
# order) are accepted and rejected; then client/tlsend's TESTS under
# -tags relaytrace, every direction's trace accepted.
terun() {
	tego=$(grep -ohE 'c\.trace\("[A-Za-z]+"' client/tlsend/*.go | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u)
	for e in $(grep -oE 'E\.ev = "[A-Za-z]+"' spec/TraceTLSEnd.tla | grep -ohE '"[A-Za-z]+"' | tr -d '"' | sort -u); do
		echo "$tego" | grep -qx "$e" || { echo "spec/TraceTLSEnd.tla: event $e is recorded by no trace call of client/tlsend"; return 1; }
	done
	for f in spec/testdata/accept-tlsend-*.ndjson spec/testdata/reject-tlsend-*.ndjson; do
		cp "$f" "$work/"
		want=accepted
		case $f in *reject-*) want=rejected ;; esac
		got=rejected
		! tetrace "$work/$(basename "$f")" || got=accepted
		grep -q 'distinct states found' "$work/$(basename "$f").out" || { echo "$f: TLC failed:"; tail -20 "$work/$(basename "$f").out"; return 1; }
		[ $got = $want ] || { echo "$f: $got, want $want"; return 1; }
		echo "$f: $got"
	done
	d=$work/tetraces
	mkdir -p "$d"
	(cd client && RELAYTRACE=$d go test -tags relaytrace -count=1 -run "$1" ./tlsend/) >"$work/tetest.out" 2>&1 || {
		cat "$work/tetest.out"
		return 1
	}
	nt=0 fail=0
	for f in "$d"/tlsend-*.ndjson; do
		[ -s "$f" ] || continue
		nt=$((nt + 1))
		if tetrace "$f"; then
			echo "trace $(basename "$f"): $(wc -l <"$f" | tr -d ' ') lines: accepted"
		else
			echo "trace $(basename "$f"): REJECTED"
			grep -E 'Error|unknown event' "$f.out" | head -5
			fail=1
		fi
	done
	cat "$d"/tlsend-*.ndjson >"$d/all" 2>/dev/null || true
	for e in $(echo "$tego"); do
		printf '%s %s; ' "$e" "$(grep -c "\"ev\":\"$e\"" "$d/all" || true)"
	done
	echo
	echo "$nt traces"
	[ "$nt" -gt 0 ] || fail=1
	return $fail
}

fail=0
cfg=
# The stop tests traces records: three stops with a dead peer, a target's
# reset, an nf1 session's drain then reset, an agent without a drain (its
# two calls together), a session refused after the drain (STOPGAP);
# stoptraces (make ci) SENDCUT's two and STOPGAP's.
STOPCI='^(TestDirectStopsWaitOneGrace|TestDirectTargetResetResetsTheSession|TestDirectStopRefusesLateSessions)$'
STOPTESTS='^(TestDirectStopsWaitOneGrace|TestDirectTargetResetResetsTheSession|TestDirectStopRefusesLateSessions|TestDirectStopDrainsThenResets|TestStopResetsDirectSessionsBeforeClose)$'
# The punch tests ptraces records: a learned winner, an offered winner, a
# refused rogue, a re-punch, a retried round, a round that ends relayed,
# the port mapping's rounds in PCP, NAT-PMP and UPnP-IGD.
PTESTS='^(TestDirectSymmetricAgentGoesDirectPeerReflexively|TestDirectPunchPrefersLAN|TestDirectMappedAgentGoesDirect|TestDirectPortMapLease|TestDirectPortMapPCP|TestDirectPortMapSwitchDeletesOld|TestDirectPortMapUPnP|TestDirectPortMapUPnPPermanentOnly|TestPortMapNoMapAfterClose|TestDirectSessionMovesAndFallsBack|TestDirectModelBindings|TestDirectAgentRebindDirectAgain|TestDirectPunchRetriesAfterNoAnswer|TestDirectPunchRoundEndsRelayedAfterThreeAttempts)$'
# client/agent's tests that move an association direct: their DatagramAssoc
# traces (BindA, BindC, the direct carriers, PathLoss).
# The CallCredit tests of client/rpcclient whose two agents (or several
# senders) give TraceCallCreditBoth.tla and TraceCallCreditSenders.tla runs.
CCTESTS='^(TestCallCreditBothWaysGrant|TestCallCreditCallerLeavesStuckHandler|TestCallCreditSendersWaitForTheCaller|TestConcurrentServerStreamSend|TestFullRoundTrip)$'
DGDIRECT='^(TestDatagramDirectMovesAndFallsBack|TestDatagramDirectOnlyOnceTheAgentAttached)$'
case ${1:-} in
check)
	cfgs="CallCredit CallCreditBoth CallCreditSenders CallLifecycle CallLifecycleRetry A2ASession UDPFlow UDPFlowLive DatagramAssoc DatagramAssocTwo DatagramAssocMove DatagramAssocLive BrowserPeer DirectPunch PunchRound PunchRoundSym PortMap Birthday AgentStop AgentStopNoDrain AgentStopLate AgentStopClose TLSEnd AuditLog AuditLogLive MoveAudit"
	[ -z "${LARGE:-}" ] || cfgs="$cfgs CallCreditLarge CallCreditBothLarge UDPFlowLarge"
	# check1 CFG MODULE: one configuration, side by side (scripts/pool.sh).
	check1() {
		echo "== $1.cfg"
		st=0
		META=$work/states-$1 tlc $1.cfg $2.tla >"$work/out-$1" 2>&1 || st=$?
		grep -E '^[0-9]+ states generated|depth of|Finished in|Error|violated' "$work/out-$1" || true
		[ -z "${COVERAGE:-}" ] || grep -E '^<[A-Za-z]+.*>: 0:0$' "$work/out-$1" | sed 's/^/never taken: /' || true
		[ $st = 0 ] || { tail -60 "$work/out-$1"; return $st; }
	}
	pool_start "$work/pool"
	for c in $cfgs; do
		m=${c%Large}
		m=${m%Retry}
		m=${m%Live}
		m=${m%Two}
		m=${m%Move}
		m=${m%NoDrain}
		m=${m%Late}
		m=${m%Close}
		m=${m%Sym}
		pool check1 $c $m
	done
	pool_end
	;;
mutants)
	# expect NAME SED...: $model.cfg (or $cfg.cfg) edited must violate a
	# property; the checks run side by side (scripts/pool.sh), each with
	# its own config, output and state directory.
	pool_start "$work/pool"
	nm=0
	expect() {
		name=$1
		shift
		nm=$((nm + 1))
		sed "$@" spec/${cfg:-$model}.cfg >"$work/Mutant$nm.cfg"
		pool expect1 "$name" "$work/Mutant$nm.cfg" $model.tla "$work/m$nm"
	}
	# expect1 NAME CFG MODULE OUT: one mutant (or witness) caught.
	expect1() {
		if META=$4.states tlc "$2" "$3" >"$4.out" 2>&1; then
			echo "$1: not caught"
			return 1
		elif grep -qE '^Error: (Invariant .* is violated|Temporal propert.* was violated|Action propert.* is violated)' "$4.out"; then
			echo "$1: caught: $(grep -m1 -E '^Error: (Invariant|Temporal|Action)' "$4.out" | sed 's/^Error: //')"
		else
			echo "$1: TLC failed:"
			tail -20 "$4.out"
			return 1
		fi
	}
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
	# lane DGRAMBIND: a datagram sent direct to an end not yet bound there
	expect DA:client-binds-first -e 's/Mutant = "none"/Mutant = "client-binds-first"/'
	expect DA:agent-sends-unheard -e 's/Mutant = "none"/Mutant = "agent-sends-unheard"/'
	expect witness:DA-Revoked -e 's/^    NoHOL$/    W_Revoked/'
	expect witness:DA-Refused -e 's/^    NoHOL$/    W_Refused/'
	expect witness:DA-AmpDrop -e 's/^    NoHOL$/    W_AmpDrop/'
	expect witness:DA-Reply -e 's/^    NoHOL$/    W_Reply/'
	expect witness:DA-HalfBound -e 's/^    NoHOL$/    W_HalfBound/'
	expect witness:DA-Heard -e 's/^    NoHOL$/    W_Heard/'
	cfg=DatagramAssocMove
	expect DA:tag-unchecked -e 's/Mutant = "none"/Mutant = "tag-unchecked"/'
	expect witness:DA-Direct -e 's/^    NoHOL$/    W_Direct/'
	expect witness:DA-Moved -e 's/^    NoHOL$/    W_Moved/'
	expect witness:DA-StaleTag -e 's/^    NoHOL$/    W_StaleTag/'
	expect witness:DA-EarlyReply -e 's/^    NoHOL$/    W_EarlyReply/'
	cfg=DatagramAssocTwo
	# A reused id breaks ClosedFinal (an action property) first; with it
	# taken out the same trace reaches NoCrossFlow.
	expect DA:reuse-id -e 's/Mutant = "none"/Mutant = "reuse-id"/' -e '/^PROPERTIES$/d' -e '/ClosedFinal/d'
	expect DA:no-agent-cap -e 's/Mutant = "none"/Mutant = "no-agent-cap"/'
	expect DA:no-client-cap -e 's/Mutant = "none"/Mutant = "no-client-cap"/' -e 's/MaxFlowsC = 2/MaxFlowsC = 1/'
	expect witness:DA-FlowRefused -e 's/^    NoHOL$/    W_FlowRefused/'
	# lane NF1UDPBOUND: a refusal with room in the association (the service's bound)
	expect witness:DA-RefusedWithRoom -e 's/^    NoHOL$/    W_RefusedWithRoom/'
	cfg=DatagramAssocLive
	expect DA:no-idle -e 's/Mutant = "none"/Mutant = "no-idle"/'
	cfg=
	model=DirectPunch
	# Peer-reflexive candidates (design, lane NATSYM): each failure the punch
	# prevents, put in.
	for m in no-tag no-cap no-cert-check keep-loser return-early no-bound first-wins give-up-at-bound wait-qad; do
		expect DP:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	for w in W_PrflxWon W_OfferedWon W_Relayed W_RogueRefused W_LoserClosed W_LanReplaced W_NonLanWon W_TrickledWon W_LanBeforeQAD; do
		expect witness:DP-$w -e "s/^    TypeOK\$/    $w/"
	done
	cfg=
	model=PunchRound
	# A punch round's timing and retries (design, lane HOLEPUNCH): each
	# failure the round prevents, put in; unbounded and no-fallback need a
	# pair no punch passes.
	for m in dial-before-sync stale-rtt retry-refused wait-vanished block-during-punch; do
		expect PR:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	# The relay's asymmetry past twice the direct delay: the first Initial
	# can beat the probe (the assumption InitialAfterProbe needs).
	expect PR:asymmetry -e 's/Delays = {1, 3}/Delays = {1, 5}/'
	for w in W_DirectFirst W_DirectRetry W_VanishedRelayed W_Refused; do
		expect witness:PR-$w -e "s/^    TypeOK\$/    $w/"
	done
	cfg=PunchRoundSym
	for m in unbounded no-fallback; do
		expect PR:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	expect witness:PR-W_RelayedAfterRetries -e 's/^    TypeOK$/    W_RelayedAfterRetries/'
	cfg=
	model=PortMap
	# A direct endpoint's port mapping in PCP, NAT-PMP and UPnP-IGD (design,
	# lane HARDNAT): a mapping made after the close (the NAT-PMP code before
	# HARDNAT), every protocol's answer kept, a permanent lease, no delete.
	for m in map-after-close ask-all accept-permanent no-delete; do
		expect PM:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	for w in W_Held W_FellBackToUPnP W_Switched W_ClosedInFlight W_PermRefused W_Stale; do
		expect witness:PM-$w -e "s/^    TypeOK\$/    $w/"
	done
	model=Birthday
	# Birthday probing for an easy/hard pair (design, lane HARDNAT): a
	# spray past its count or rate, to a third party, from a hard/hard pair
	# or before an attempt failed, auxiliary sockets left open, a return
	# before they close, every hit kept, a learned address not dialled.
	for m in no-cap no-pace any-target keep-aux return-early keep-all no-dial; do
		expect BD:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	expect BD:spray-hard-hard -e 's/Mutant = "none"/Mutant = "spray-hard-hard"/' -e 's/EdmE = FALSE/EdmE = TRUE/'
	expect BD:spray-first -e 's/Mutant = "none"/Mutant = "spray-first"/' -e 's/FirstFailed = TRUE/FirstFailed = FALSE/'
	for w in W_Hit W_Miss W_LostHit W_OthersClosed; do
		expect witness:BD-$w -e "s/^    TypeOK\$/    $w/"
	done
	model=BrowserPeer
	# An nf1 address in a browser (design, lane BROWSERPEER): each failure
	# the control session, connection and stream lifecycle prevents, put in.
	for m in retry-other-path pc-before-admit no-dc-cap pc-outlives-ctl dc-without-pc no-break; do
		expect BP:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	for w in W_DoneDC W_DoneWSAfterFail W_Failed W_ReapedAfterCtl; do
		expect witness:BP-$w -e "s/^    TypeOK\$/    $w/"
	done
	model=AgentStop
	# An agent's stop (lane STOPSPEC): SENDCUT's two halves (a target's
	# reset did not reach its direct session; the drain waited for a reset
	# session), SENDCUT's three graces (each stop call its own), SENDBEST's
	# second Listener.Close returning at once, a stop with no drain, a
	# reset seen as a clean end, a connection closed at once (no grace).
	for m in no-target-cut drain-waits-reset grace-per-stop second-close-returns no-drain reset-as-close no-grace; do
		expect STOP:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	# SENDCUT's target reset also breaks the one-grace bound from the reset.
	expect STOP:no-target-cut-grace -e 's/Mutant = "none"/Mutant = "no-target-cut"/' -e '/^PROPERTIES$/d' -e '/NoDrainOnReset/d'
	for w in W_GoneCut W_FullBound W_StopReset W_Eof W_ResetCut W_DrainWaits W_SecondClose; do
		expect witness:STOP-$w -e "s/^    TypeOK\$/    $w/"
	done
	cfg=AgentStopLate
	# A session registered once a drain ended put in the table unreset
	# (lane STOPGAP): it moves to its direct path after the last call's
	# sessions were taken and outlives the exit; beside a session there at
	# the stop, a later call waits a fresh grace for it past the bound.
	expect STOPLATE:late-unreset -e 's/Mutant = "none"/Mutant = "late-unreset"/'
	expect STOPLATE:late-unreset-grace -e 's/Mutant = "none"/Mutant = "late-unreset"/' -e 's/^    l1 = l1$/    l1 = l1\n    d1 = d1/' \
		-e 's/Sessions = {l1}/Sessions = {d1, l1}/' -e 's/Direct = {l1}/Direct = {d1, l1}/' -e 's/MaxBytes = 1/MaxBytes = 0/' -e '/ExitAfterEnd/d'
	for w in W_LateMoved W_LateRefused; do
		expect witness:STOPLATE-$w -e "s/^    TypeOK\$/    $w/"
	done
	cfg=AgentStopClose
	# An accepted session's Close returned at once (lane DIRECTCLOSE,
	# PIPEMATRIX defect 1): its program exited 0 and the stop's bounded
	# drain reset the tail.
	expect STOPCLOSE:close-returns-early -e 's/Mutant = "none"/Mutant = "close-returns-early"/'
	for w in W_CloseClean W_CloseErr; do
		expect witness:STOPCLOSE-$w -e "s/^    TypeOK\$/    $w/"
	done
	cfg=AgentStopNoDrain
	# Without a drain the primary's and the cycle's calls run together.
	for m in grace-per-stop second-close-returns no-grace; do
		expect STOP0:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	cfg=
	model=TLSEnd
	# A session's end under end-to-end TLS (lane PIPERESET): a Close at the
	# peer's close_notify, before the FIN behind it (the code before); a
	# Close that waits for that FIN with no bound.
	for m in close-at-notify unbounded; do
		expect TLSEND:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	expect witness:Clean -e 's/^    NoFalseReset$/    W_Clean/'
	expect witness:Bound -e 's/^    NoFalseReset$/    W_Bound/'
	model=AuditLog
	# A machine's session audit log (lane SA5GAPS): recovery of a killed
	# process's sessions and the file's rotation.
	for m in recover-live recover-no-log-check rotate-unacked rotate-all; do
		expect AUDIT:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	cfg=AuditLogLive
	for m in no-recovery open-before-intent rotate-drops-open; do
		expect AUDIT:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	cfg=
	for w in W_LostClose W_CloseThenKilled W_IntentOnly W_Rotated; do
		expect witness:$w -e "s/^    OneLog\$/    $w/"
	done
	model=MoveAudit
	# The session audit across an organisation move (lane SA5GAPS).
	for m in bundle-no-sessions take-after-fence; do
		expect MOVEAUDIT:$m -e "s/Mutant = \"none\"/Mutant = \"$m\"/"
	done
	for w in W_TakenAfterMove W_AckedBeforeMove; do
		expect witness:$w -e "s/^    NoGap\$/    $w/"
	done
	pool_end || fail=1
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
bptraces)
	# The per-push slice: a session with two streams and one whose
	# visitor closed its connection.
	bprun "${BP_TRACE_TESTS:-^TestBrowserDirect(ServesStreamsOnDataChannels|VisitorConnectionGone)\$}" || fail=1
	exit $fail
	;;
dgtraces)
	dgrun "${DG_TRACE_TESTS:-^TestDatagramAssocTrace(Revoke)?\$}" "${DG_TRACE_COUNT:-3}" || fail=1
	dgrun "${DG_DIRECT_TESTS:-$DGDIRECT}" "${DG_TRACE_COUNT:-3}" agent || fail=1
	exit $fail
	;;
ptraces)
	prun "${P_TRACE_TESTS:-$PTESTS}" || fail=1
	exit $fail
	;;
stoptraces)
	stoprun "${STOP_TRACE_TESTS:-$STOPCI}" || fail=1
	exit $fail
	;;
tetraces)
	# A session's end under end-to-end TLS over a link session (lane
	# ENDTRACE): its fixtures and client/tlsend's end tests.
	terun "${TE_TRACE_TESTS:-^TestEndOverALinkSession\$}" || fail=1
	exit $fail
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
ccruns)
	ccrun "${CC_TRACE_TESTS:-$CCTESTS}" || fail=1
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
	ccrun "${CC_TRACE_TESTS:-$CCTESTS}" || exit 1
	asrun "${AS_TRACE_TESTS:-^TestA2AE2EE}" || exit 1
	dgrun "${DG_TRACE_TESTS:-^TestDatagramAssocTrace(Revoke)?\$}" "${DG_TRACE_COUNT:-3}" || exit 1
	dgrun "${DG_DIRECT_TESTS:-$DGDIRECT}" "${DG_TRACE_COUNT:-3}" agent || exit 1
	prun "${P_TRACE_TESTS:-$PTESTS}" || exit 1
	stoprun "${STOP_TRACE_TESTS:-$STOPTESTS}" fixtures || exit 1
	bprun "${BP_TRACE_TESTS:-^(TestBrowserDirect|TestBrowserPeerModelBindings)}" || exit 1
	terun "${TE_TRACE_TESTS:-^TestEndOverALinkSession\$}" || exit 1
	auditrun || exit 1
	;;
audittraces)
	# A machine's session audit log and the audit across a move (lane
	# SA5TRACE): their fixtures and the audit tests' traces (traces runs it).
	auditrun || fail=1
	exit $fail
	;;
*)
	echo "usage: spec.sh check|mutants|traces|cltraces|astraces|dgtraces|ptraces|stoptraces|bptraces|ccruns|cctraces FILE..." >&2
	exit 2
	;;
esac
