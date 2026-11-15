#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# spec-orgmove.sh ci|check|live|mutants|witnesses|coverage|fixtures|traces|trace F: the TLA+ model of
# moving an organisation's issuer to another machine (spec/orgmove/README.md).
#   check     TLC on spec/orgmove/OrgMove.cfg: every invariant.
#   live      TLC on spec/orgmove/OrgMoveLive.cfg: MoveCompletes.
#   mutants   each line of spec/orgmove/mutants.txt must be caught.
#   witnesses each Witness* must be violated (reachable).
#   coverage  check with -coverage 1; fails on an action never taken.
#   ci        check, live, mutants, witnesses, coverage, fixtures
#             (make spec-orgmove-ci).
#   repeat    TLC on spec/orgmove/OrgMoveRepeat.cfg: two moves in a row
#             (about a minute; by hand).
#   fixtures  each spec/orgmove/traces/<Invariant>-*.ndjson is rejected by
#             spec/orgmove/TraceOrgMove.tla's <Invariant>.
#   traces    the tests of org/orgpki, orgissuer and orgenrol built
#             -tags enroltrace, each test's ORGMOVETRACE lines checked by
#             TraceOrgMove.tla; then the fixtures.
#   trace F   one trace file.
#   holds     the relay's holds across a move (spec/orgmove/OrgHolds.tla):
#             OrgHolds.cfg, OrgHoldsLive.cfg, each line of
#             spec/orgmove/holds-mutants.txt caught, its witnesses
#             reached, -coverage 1 (in ci).
# TLC_WORKERS (default 2) caps TLC's threads, TLC_HEAP (default 1g) its
# heap. Java and tla2tools.jar come from scripts/fetch-tla.sh.
set -eu
cd "$(dirname "$0")/.."
tools=$(scripts/fetch-tla.sh)
java=$(echo "$tools" | sed -n 1p)
jar=$(echo "$tools" | sed -n 2p)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dir=spec/orgmove
spec=OrgMove
temporal="MoveCompletes"
actprops=""
mfile=mutants.txt
witnesses="WitnessMoved WitnessTokenAcrossMove WitnessRevokedAcrossMove WitnessResentAfterLoss WitnessOldWiped WitnessCrashedThenMoved WitnessBackupRefused"
# OrgHolds.tla: its actions taken only under a mutant (coverage skips them).
holds_spec() {
	spec=OrgHolds
	actprops="HolderKeeps"
	mfile=holds-mutants.txt
	witnesses="WitnessMoved WitnessMovedBack WitnessBackUnpublished WitnessTakenVacant WitnessLateWrite WitnessFinished WitnessReturnToFinished"
	covskip="EarlyRelease|XRelease"
}

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
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Conforms\n    AtMostOneIssuer\n    OldCannotIssue\n    ImportFenced\n    CRLMonotone\n    TraceDone\n' "$t" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TraceOrgMove.tla) >"$t.out" 2>&1 || true
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
	for pkg in org/orgpki org/orgissuer org/orgenrol; do
		b=$(basename $pkg)
		(cd org && go test -tags enroltrace -c -o "$work/$b.test" ./${pkg#org/}/)
		"$work/$b.test" -test.list '^Test' >"$work/$b.tests"
		while read -r name; do
			mkdir -p "$work/unit/$b-$name"
			(cd $pkg && ORGMOVETRACE=$work/unit/$b-$name "$work/$b.test" -test.run "^$name\$" -test.count 1 -test.timeout 10m >"$work/unit/$b-$name.out" 2>&1) ||
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
check) run OrgMove.cfg ;;
live) run OrgMoveLive.cfg ;;
repeat) run OrgMoveRepeat.cfg ;;
mutants) mutants ;;
witnesses) witnesses ;;
coverage) coverage ;;
ci) run OrgMove.cfg && run OrgMoveLive.cfg && mutants && witnesses && coverage && fixtures &&
	holds_spec && run OrgHolds.cfg && run OrgHoldsLive.cfg && mutants && witnesses && coverage ;;
holds) holds_spec && run OrgHolds.cfg && run OrgHoldsLive.cfg && mutants && witnesses && coverage ;;
fixtures) fixtures ;;
traces) traces ;;
trace) trace "$2" ;;
*) sed -n '4,22p' "$0" >&2; exit 2 ;;
esac
