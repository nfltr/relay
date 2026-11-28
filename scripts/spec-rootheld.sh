#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# spec-rootheld.sh ci|check|full|live|mutants|witnesses|coverage: the TLA+ model
# of the root-held member log (spec/rootheld/README.md; a design: no code
# and so no trace recorder yet, lane RH1 adds it with the code).
#   check     TLC on spec/rootheld/MemberLog.cfg: every invariant.
#   full      the same on MemberLogTwo.cfg, two verifiers (nightly: make spec-traces).
#   live      TLC on spec/rootheld/MemberLogLive.cfg: RemovalTakesEffect.
#   mutants   each line of spec/rootheld/mutants.txt must be caught.
#   witnesses each W_* must be violated (reachable).
#   coverage  check with -coverage 1; fails on an action never taken.
#   ci        check, live, mutants, witnesses, coverage (make spec-rootheld-ci).
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
dir=spec/rootheld
spec=MemberLog
temporal="RemovalTakesEffect"
actprops=""
mfile=mutants.txt
# Sync is a Deliver of the canonical head, apart only for its fairness
# (LiveSpec): it reaches no state Deliver does not, so coverage skips it.
covskip=Sync
witnesses="W_AdminAdmits W_RevokedForkRefused W_ForkSeen W_IssuerRefused W_RemovedOffChain"
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

case ${1:-} in
check) run MemberLog.cfg ;;
full) run MemberLogTwo.cfg ;;
live) run MemberLogLive.cfg ;;
mutants) mutants ;;
witnesses) witnesses ;;
coverage) coverage ;;
ci) run MemberLog.cfg && run MemberLogLive.cfg && mutants && witnesses && coverage ;;
*) sed -n '4,13p' "$0" >&2; exit 2 ;;
esac
