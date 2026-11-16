#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# spec-appenrol.sh ci|check|mutants|witnesses|coverage: the TLA+ model of an
# app's device enrolled for a person (spec/appenrol/README.md).
#   check     TLC on spec/appenrol/AppEnrol.cfg: every invariant.
#   mutants   each line of spec/appenrol/mutants.txt must be caught.
#   witnesses each Witness* must be violated (reachable).
#   coverage  check with -coverage 1; fails on an action never taken.
#   fixtures  each spec/appenrol/traces/<Invariant>-*.ndjson is rejected by
#             TraceAppEnrol.tla's <Invariant>.
#   traces    the tests of org/orgpki and org/orgenrol built -tags
#             enroltrace (APPENROLTRACE), each trace checked by
#             TraceAppEnrol.tla, then the fixtures (make spec-appenrol-traces).
#   trace F   one trace file.
#   ci        check, mutants, witnesses, coverage, fixtures (make spec-appenrol-ci).
# TLC_WORKERS (default 2) caps TLC's threads, TLC_HEAP (default 1g) its
# heap. Java and tla2tools.jar come from scripts/fetch-tla.sh.
set -eu
cd "$(dirname "$0")/.."
tools=$(scripts/fetch-tla.sh)
java=$(echo "$tools" | sed -n 1p)
jar=$(echo "$tools" | sed -n 2p)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dir=spec/appenrol
spec=AppEnrol
temporal=""
actprops=""
mfile=mutants.txt
witnesses="WitnessSSOEnrol WitnessCodeEnrol WitnessRenewed WitnessReauth WitnessDisabledStillLive WitnessUserRevoked WitnessAppRevoked"
tlc() {
	cfg_=$1
	shift
	(cd $dir && "$java" -Xmx"${TLC_HEAP:-1g}" -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "${TLC_WORKERS:-2}" \
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

# consts [cfg]: a config's constants ($spec.cfg's by default), Mutant aside.
consts() { sed -n '/^CONSTANTS/,/^SPECIFICATION/p' $dir/${1:-$spec.cfg} | grep -v -e Mutant -e '^SPECIFICATION'; }

mutants() {
	: >"$work/fails"
	grep -v '^#' $dir/$mfile | while read -r m p c; do
		[ -n "$m" ] || continue
		case " $temporal " in
		*" $p "*) { consts $c; printf '    Mutant = "%s"\nSPECIFICATION LiveSpec\nPROPERTIES\n    %s\n' "$m" "$p"; } >"$work/X-$m-$p.cfg"
			want="^Error: Temporal propert(y|ies) .*violated" ;;
		*)
			case " $actprops " in
			*" $p "*) { consts $c; printf '    Mutant = "%s"\nSPECIFICATION Spec\nPROPERTIES\n    %s\n' "$m" "$p"; } >"$work/X-$m-$p.cfg"
				want="^Error: Action property $p .*violated" ;;
			*) { consts $c; printf '    Mutant = "%s"\nSPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    %s\n' "$m" "$p"; } >"$work/X-$m-$p.cfg"
				want="^Error: Invariant $p is violated" ;;
			esac ;;
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
	if grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out" | grep -Ev "^<(${covskip:-^})[ (]" | grep -qE ': 0:|: 0$'; then
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
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Conforms\n    AttrsFixed\n    SignInBindsKey\n    CodeOnce\n    DisabledUserBound\n    RevokedUserCut\n    RevokedAppCut\n    TraceDone\n' "$t" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TraceAppEnrol.tla) >"$t.out" 2>&1 || true
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

# traces: every test of the packages, one trace directory each; the
# events seen (an event or refusal no test makes is a test gap).
traces() {
	: >"$work/fails"
	for pkg in org/orgpki org/orgenrol; do
		b=$(basename $pkg)
		(cd org && go test -tags enroltrace -c -o "$work/$b.test" ./${pkg#org/}/)
		"$work/$b.test" -test.list '^Test' >"$work/$b.tests"
		while read -r name; do
			mkdir -p "$work/unit/$b-$name"
			(cd $pkg && APPENROLTRACE=$work/unit/$b-$name "$work/$b.test" -test.run "^$name\$" -test.count 1 -test.timeout 10m >"$work/unit/$b-$name.out" 2>&1) ||
				{ echo "$b $name: test failed"; tail -20 "$work/unit/$b-$name.out"; echo x >>"$work/fails"; }
		done <"$work/$b.tests"
	done
	n=0
	for f in "$work"/unit/*/*.ndjson; do
		[ -f "$f" ] || continue
		n=$((n + 1))
		trace "$f" >"$work/t.out" || { echo "$f"; cat "$work/t.out"; echo x >>"$work/fails"; }
	done
	echo "events: $(cat "$work"/unit/*/*.ndjson 2>/dev/null | sed -E 's/.*"ev":"([a-z]+)".*/\1/' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
	echo "refusals: $(cat "$work"/unit/*/*.ndjson 2>/dev/null | grep '"ev":"refuse"' | sed -E 's/.*"why":"([a-z]*)".*/\1/' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
	echo "$n traces, $(wc -l <"$work/fails" | tr -d ' ') failed"
	fixtures || echo x >>"$work/fails"
	[ ! -s "$work/fails" ]
}

case ${1:-} in
check) run AppEnrol.cfg ;;
mutants) mutants ;;
witnesses) witnesses ;;
coverage) coverage ;;
ci) run AppEnrol.cfg && mutants && witnesses && coverage && fixtures ;;
fixtures) fixtures ;;
traces) traces ;;
trace) trace "$2" ;;
*) sed -n '4,19p' "$0" >&2; exit 2 ;;
esac
