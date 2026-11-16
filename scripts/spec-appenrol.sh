#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# spec-appenrol.sh ci|check|mutants|witnesses|coverage: the TLA+ model of an
# app's device enrolled for a person (spec/appenrol/README.md).
#   check     TLC on spec/appenrol/AppEnrol.cfg: every invariant.
#   mutants   each line of spec/appenrol/mutants.txt must be caught.
#   witnesses each Witness* must be violated (reachable).
#   coverage  check with -coverage 1; fails on an action never taken.
#   ci        all of them (make spec-appenrol-ci).
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

case ${1:-} in
check) run AppEnrol.cfg ;;
mutants) mutants ;;
witnesses) witnesses ;;
coverage) coverage ;;
ci) run AppEnrol.cfg && mutants && witnesses && coverage ;;
*) sed -n '4,12p' "$0" >&2; exit 2 ;;
esac
