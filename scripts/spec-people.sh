#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# spec-people.sh ci|check|mutants|witnesses|coverage: the TLA+ model of the people
# layer: persons, roles, invites, offboarding (spec/people/README.md).
#   check     TLC on spec/people/People.cfg: every invariant.
#   mutants   each line of spec/people/mutants.txt must be caught.
#   witnesses each Witness* must be violated (reachable).
#   coverage  check with -coverage 1; fails on an action never taken.
#   fixtures  each spec/people/traces/<Invariant>-*.ndjson is rejected by
#             TracePeople.tla's <Invariant>.
#   traces    the tests of org/orgpki and org/orgenrol built -tags
#             enroltrace (PEOPLETRACE), each trace checked by
#             TracePeople.tla, then the fixtures (make spec-traces).
#   trace F   one trace file.
#   ci        coverage (the check with -coverage 1), mutants, witnesses,
#             fixtures (make spec-people-ci).
# TLC_WORKERS (default 2) caps TLC's threads. Java (its heap capped) and
# tla2tools.jar come from scripts/fetch-tla.sh.
set -eu
cd "$(dirname "$0")/.."
tools=$(scripts/fetch-tla.sh)
java=$(echo "$tools" | sed -n 1p)
jar=$(echo "$tools" | sed -n 2p)
work=$(mktemp -d)
# TLC runs go through scripts/cicache.sh: kept only when this script passes.
cicache=$PWD/scripts/cicache.sh
CICACHE_STAGE=$("$cicache" begin || true)
export CICACHE_STAGE
trap 'st=$?; "$cicache" end "$CICACHE_STAGE" $st || st=1; rm -rf "$work"; exit $st' EXIT
. "$PWD/scripts/pool.sh"
dir=spec/people
spec=People
temporal=""
actprops="RemovedStaysOut"
mfile=mutants.txt
witnesses="WitnessJoined WitnessAdminActs WitnessSecondMachine WitnessRoleChanged WitnessWindow WitnessOffboardReached WitnessLostLaptop WitnessGranted"
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

# consts [cfg]: a config's constants ($spec.cfg's by default), Mutant aside.
consts() { sed -n '/^CONSTANTS/,/^SPECIFICATION/p' $dir/${1:-$spec.cfg} | grep -v -e Mutant -e '^SPECIFICATION'; }

# mutant1 M P WANT: one mutant, caught when its TLC output matches WANT (a pool check).
mutant1() {
	tlc "$work/X-$1-$2.cfg" >"$work/x-$1-$2.out" 2>&1 || true
	if grep -Eq "$3" "$work/x-$1-$2.out"; then
		echo "$1: caught by $2 ($(grep -c '^State [0-9]*:' "$work/x-$1-$2.out") states deep)"
	else
		echo "$1: NOT caught by $2"
		grep -m3 -E '^Error' "$work/x-$1-$2.out" || true
		return 1
	fi
}

mutants() {
	grep -v '^#' $dir/$mfile >"$work/mlist"
	pool_start "$work/pool"
	while read -r m p c; do
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
		pool mutant1 "$m" "$p" "$want"
	done <"$work/mlist"
	pool_end
}

# witness1 W: the witness W reached (violated; a pool check).
witness1() {
	tlc "$work/W-$1.cfg" >"$work/w-$1.out" 2>&1 || true
	if grep -q "^Error: Invariant $1 is violated" "$work/w-$1.out"; then
		echo "$1: reached"
	else
		echo "$1: NOT reached"
		return 1
	fi
}

witnesses() {
	pool_start "$work/pool"
	for w in $witnesses; do
		{ consts; printf '    Mutant = "none"\nSPECIFICATION Spec\nINVARIANTS\n    %s\n' "$w"; } >"$work/W-$w.cfg"
		pool witness1 "$w"
	done
	pool_end
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
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Conforms\n    AuthorizedActs\n    AdminsByOwner\n    JoinNeedsInvite\n    NoOrphan\n    ReachBound\n    RemovedStaysOut\n    TraceDone\n' "$t" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TracePeople.tla) >"$t.out" 2>&1 || true
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
# events seen (an event no test makes is a test gap).
traces() {
	: >"$work/fails"
	for pkg in org/orgpki org/orgenrol; do
		b=$(basename $pkg)
		(cd org && go test -tags enroltrace -c -o "$work/$b.test" ./${pkg#org/}/)
		"$work/$b.test" -test.list '^Test' >"$work/$b.tests"
		while read -r name; do
			mkdir -p "$work/unit/$b-$name"
			(cd $pkg && PEOPLETRACE=$work/unit/$b-$name "$work/$b.test" -test.run "^$name\$" -test.count 1 -test.timeout 10m >"$work/unit/$b-$name.out" 2>&1) ||
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
	echo "$n traces, $(wc -l <"$work/fails" | tr -d ' ') failed"
	fixtures || echo x >>"$work/fails"
	[ ! -s "$work/fails" ]
}

case ${1:-} in
check) run People.cfg ;;
fixtures) fixtures ;;
traces) traces ;;
trace) trace "$2" ;;
mutants) mutants ;;
witnesses) witnesses ;;
coverage) coverage ;;
ci) coverage && mutants && witnesses && fixtures ;;
*) sed -n '4,18p' "$0" >&2; exit 2 ;;
esac
