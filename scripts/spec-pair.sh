#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# spec-pair.sh ci|check|live|mutants|witnesses|coverage|fixtures|traces|trace F:
# the TLA+ model of replacing a machine's key and certificate as one pair
# (spec/pair/README.md).
#   check     TLC on spec/pair/MachinePair.cfg: every invariant.
#   live      TLC on spec/pair/MachinePairLive.cfg: ReaderCompletes.
#   mutants   each line of spec/pair/mutants.txt must be caught.
#   witnesses each Witness* must be violated (reachable).
#   coverage  check with -coverage 1; fails on an action never taken.
#   fixtures  each spec/pair/traces/<Invariant>-*.ndjson is rejected by
#             spec/pair/TraceMachinePair.tla's <Invariant>.
#   traces    client/pairfile's tests built -tags pairtrace, each test's
#             PAIRTRACE lines checked by TraceMachinePair.tla; then the
#             fixtures.
#   ci        check, live, mutants, witnesses, coverage, traces
#             (make spec-pair-ci).
#   trace F   one trace file.
# TLC_WORKERS (default 2) caps TLC's threads. Java (its heap capped) and
# tla2tools.jar come from scripts/fetch-tla.sh.
set -eu
cd "$(dirname "$0")/.."
tools=$(scripts/fetch-tla.sh)
java=$(echo "$tools" | sed -n 1p)
jar=$(echo "$tools" | sed -n 2p)
work=$(mktemp -d)
cicache=$PWD/scripts/cicache.sh
CICACHE_STAGE=$("$cicache" begin || true)
export CICACHE_STAGE
trap 'st=$?; "$cicache" end "$CICACHE_STAGE" $st || st=1; rm -rf "$work"; exit $st' EXIT
dir=spec/pair
spec=MachinePair
temporal="ReaderCompletes"
witnesses="WitnessCrashMidSwap WitnessRolledForward WitnessReadNext WitnessReplaced"
covskip="WriteKey" # key-first's step: taken only under that mutant

tlc() {
	cfg_=$1
	shift
	(cd $dir && "$cicache" tlc -- "$java" -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "${TLC_WORKERS:-2}" \
		-noGenerateSpecTE -deadlock -metadir "$work/states-$(basename "$cfg_")" -config "$cfg_" "$@" $spec.tla)
}

run() {
	if ! tlc "$1" >"$work/c.out" 2>&1; then
		tail -40 "$work/c.out"
		echo "$1: FAILED"
		return 1
	fi
	echo "$1: ok ($(grep -m1 'distinct states found, 0 states left' "$work/c.out" | sed 's/.* generated, //; s/, 0 states left.*//'), $(grep -m1 'Finished in' "$work/c.out" | sed 's/ at .*//'))"
}

consts() { sed -n '/^CONSTANTS/,/^SPECIFICATION/p' $dir/$spec.cfg | grep -v -e Mutant -e '^SPECIFICATION'; }

mutants() {
	: >"$work/fails"
	grep -v '^#' $dir/mutants.txt | while read -r m p; do
		[ -n "$m" ] || continue
		case " $temporal " in
		*" $p "*) { consts; printf '    Mutant = "%s"\nSPECIFICATION LiveSpec\nPROPERTIES\n    %s\n' "$m" "$p"; } >"$work/X-$m-$p.cfg"
			want="^Error: Temporal propert(y|ies) .*violated" ;;
		*) { consts; printf '    Mutant = "%s"\nSPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    %s\n' "$m" "$p"; } >"$work/X-$m-$p.cfg"
			want="^Error: Invariant $p is violated" ;;
		esac
		tlc "$work/X-$m-$p.cfg" >"$work/x.out" 2>&1 || true
		if grep -Eq "$want" "$work/x.out"; then
			echo "$m: caught by $p ($(grep -c '^State [0-9]*:' "$work/x.out") states deep)"
		else
			echo "$m: NOT caught by $p"
			grep -m3 -E '^Error' "$work/x.out" || true
			echo x >>"$work/fails"
		fi
	done
	[ ! -s "$work/fails" ]
}

witnesses() {
	: >"$work/fails"
	for w in $witnesses; do
		{ consts; printf '    Mutant = "none"\nSPECIFICATION Spec\nINVARIANTS\n    %s\n' "$w"; } >"$work/W-$w.cfg"
		tlc "$work/W-$w.cfg" >"$work/w.out" 2>&1 || true
		if grep -q "^Error: Invariant $w is violated" "$work/w.out"; then
			echo "$w: reached"
		else
			echo "$w: NOT reached"
			echo x >>"$work/fails"
		fi
	done
	[ ! -s "$work/fails" ]
}

coverage() {
	tlc $spec.cfg -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
	grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out"
	if grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out" | grep -Ev "^<(${covskip})[ (]" | grep -qE ': 0:|: 0$'; then
		echo "coverage: an action is never taken"
		return 1
	fi
	echo "coverage: every action taken"
}

# trace F: accepted when every line was read with no violation.
trace() {
	t=$work/$(basename "$1")
	cat "$1" >"$t"
	[ -s "$t" ] || { echo "$1: no lines"; return 0; }
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Conforms\n    Usable\n    Ordered\n    TraceDone\n' "$t" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TraceMachinePair.tla) >"$t.out" 2>&1 || true
	if grep -q '^Error: Invariant TraceDone is violated' "$t.out"; then
		echo "$(basename "$1"): $(wc -l <"$t" | tr -d ' ') lines: accepted"
		return 0
	fi
	grep -m1 '^Error' "$t.out" || tail -20 "$t.out"
	echo "$(basename "$1"): $(wc -l <"$t" | tr -d ' ') lines: REJECTED"
	return 1
}

fixtures() {
	: >"$work/ffails"
	for f in $dir/traces/*.ndjson; do
		want=$(basename "$f" | cut -d- -f1)
		if trace "$f" >"$work/m.out"; then
			echo "$(basename "$f"): NOT rejected"
			echo x >>"$work/ffails"
		elif grep -q "^Error: Invariant $want is violated" "$work/m.out"; then
			echo "$(basename "$f"): rejected by $want"
		else
			echo "$(basename "$f"): rejected, not by $want: $(grep -m1 '^Error' "$work/m.out")"
			echo x >>"$work/ffails"
		fi
	done
	[ ! -s "$work/ffails" ]
}

traces() {
	: >"$work/fails"
	mkdir -p "$work/tr"
	(cd client && PAIRTRACE="$work/tr" go test -count=1 -tags pairtrace ./pairfile/) >"$work/go.out" 2>&1 || { tail -30 "$work/go.out"; return 1; }
	n=0
	for f in "$work"/tr/*.ndjson; do
		[ -e "$f" ] || continue
		n=$((n + 1))
		trace "$f" || echo x >>"$work/fails"
	done
	[ "$n" -gt 0 ] || { echo "traces: no trace written"; return 1; }
	[ ! -s "$work/fails" ]
	fixtures
}

case ${1:-} in
check) run $spec.cfg ;;
live) run ${spec}Live.cfg ;;
mutants) mutants ;;
witnesses) witnesses ;;
coverage) coverage ;;
fixtures) fixtures ;;
traces) traces ;;
trace) trace "$2" ;;
ci) run $spec.cfg && run ${spec}Live.cfg && mutants && witnesses && coverage && traces ;;
*)
	echo "usage: spec-pair.sh ci|check|live|mutants|witnesses|coverage|fixtures|traces|trace F" >&2
	exit 2
	;;
esac
