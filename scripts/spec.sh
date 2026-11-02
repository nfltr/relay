#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# spec.sh check|mutants: the TLA+ models of spec/ (spec/README.md).
#   check    TLC on spec/SignalConn.cfg: its invariant and liveness.
#   mutants  each bug put back must be caught.
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
	cov=
	[ -z "${COVERAGE:-}" ] || cov="-coverage 1"
	(cd spec && "$java" -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 2 $cov \
		-deadlock -noGenerateSpecTE -metadir "$work/states" -config "$c" "$mod")
}

fail=0
case ${1:-} in
check)
	echo "== SignalConn.cfg"
	st=0
	tlc SignalConn.cfg SignalConn.tla >"$work/out" 2>&1 || st=$?
	grep -E '^[0-9]+ states generated|depth of|Error|violated' "$work/out" || true
	[ -z "${COVERAGE:-}" ] || grep -E '^<[A-Za-z]+.*>: 0:0$' "$work/out" | sed 's/^/never taken: /' || true
	[ $st = 0 ] || { tail -60 "$work/out"; exit $st; }
	;;
mutants)
	# expect NAME SED...: SignalConn.cfg edited must violate a property.
	expect() {
		name=$1
		shift
		sed "$@" spec/SignalConn.cfg >"$work/Mutant.cfg"
		if tlc "$work/Mutant.cfg" SignalConn.tla >"$work/m.out" 2>&1; then
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
	exit $fail
	;;
*)
	echo "usage: spec.sh check|mutants" >&2
	exit 2
	;;
esac
