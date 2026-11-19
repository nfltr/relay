#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# spec-enrol.sh ci|check|live|mutants|witnesses|coverage|fixtures|traces|trace F: the TLA+ model of
# organisation certificates' lifecycle: renewal, revocation, root rotation
# (spec/enrol/README.md).
#   check     TLC on spec/enrol/Enrol.cfg: every invariant; Rebind.cfg:
#             the same with a rebind; Join.cfg: the
#             join by token (Join.tla); RevokePush.cfg: a revoke's events
#             and backstops (RevokePush.tla).
#   live      TLC on spec/enrol/EnrolLive.cfg: the temporal properties;
#             EnrolLoss.cfg: everything with the relay losing messages.
#   mutants   each line of spec/enrol/mutants.txt must be caught (a line
#             naming a Join*.cfg runs Join.tla).
#   witnesses each Witness* must be violated (reachable).
#   ci        check, live, mutants, witnesses, fixtures (make spec-enrol-ci).
#   coverage  check with -coverage 1; fails on an action never taken.
#   fixtures  each spec/enrol/traces/<Invariant>-*.ndjson is rejected by
#             <Invariant> of TraceEnrol.tla (in ci).
#   traces    the tests of org/orgpki, orgmachine and orgenrol built -tags
#             enroltrace, each test's trace checked by TraceEnrol.tla, then
#             the fixtures (make spec-enrol-traces).
#   trace F   one recorded trace file; ptrace F one RevokePush trace
#             (<pid>.revokepush, TraceRevokePush.tla).
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
dir=spec/enrol
temporal="TakesEffect MachinesFollowRotation"
witnesses="WitnessRenewed WitnessRevokeSeen WitnessFailClosed WitnessForgedSession WitnessRotated WitnessSessionAfterRotation WitnessRetried@EnrolLoss.cfg WitnessRebound@Rebind.cfg WitnessSessionAfterRebind@Rebind.cfg WitnessRetiredHeld@Rebind.cfg
WitnessRetriedJoin@Join.cfg WitnessReissued@Join.cfg WitnessJoinedAfterLoss@Join.cfg WitnessJoinedAfterRotation@Join.cfg WitnessRefusedOther@Join.cfg WitnessRefusedEvil@Join.cfg
WitnessCutByPush@RevokePush.cfg WitnessServeBackstop@RevokePush.cfg WitnessFollowBackstop@RevokePush.cfg WitnessHeldAfterRevoke@RevokePush.cfg"

# modof CFG: the module a config checks (Join*.cfg: Join.tla,
# RevokePush*.cfg: RevokePush.tla).
modof() { case ${1:-} in Join*) echo Join ;; RevokePush*) echo RevokePush ;; *) echo Enrol ;; esac; }

tlc() {
	cfg_=$1
	shift
	(cd $dir && "$cicache" tlc -- "$java" -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "${TLC_WORKERS:-2}" \
		-noGenerateSpecTE -deadlock -metadir "$work/states-$(basename "$cfg_")" -config "$cfg_" "$@" "${MOD:-$(modof "$cfg_")}.tla")
}

run() {
	if ! tlc "$1" >"$work/c.out" 2>&1; then
		tail -40 "$work/c.out"
		echo "$1: FAILED"
		return 1
	fi
	echo "$1: ok ($(grep -m1 'distinct states found, 0 states left' "$work/c.out" | sed 's/.* generated, //; s/, 0 states left.*//'), $(grep -m1 'Finished in' "$work/c.out" | sed 's/ at .*//'))"
}

# consts [cfg]: a config's constants (Enrol.cfg's by default), Mutant aside.
consts() { sed -n '/^CONSTANTS/,/^SPECIFICATION/p' $dir/${1:-Enrol.cfg} | grep -v -e Mutant -e '^SPECIFICATION'; }

mutants() {
	: >"$work/fails"
	grep -v '^#' $dir/mutants.txt | while read -r m p c; do
		[ -n "$m" ] || continue
		case " $temporal " in
		*" $p "*) { consts $c; printf '    Mutant = "%s"\nSPECIFICATION LiveSpec\nPROPERTIES\n    %s\n' "$m" "$p"; } >"$work/X-$m-$p.cfg"
			want="^Error: Temporal propert(y|ies) .*violated" ;;
		*) { consts $c; printf '    Mutant = "%s"\nSPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    %s\n' "$m" "$p"; } >"$work/X-$m-$p.cfg"
			want="^Error: Invariant $p is violated" ;;
		esac
		MOD=$(modof "$c") tlc "$work/X-$m-$p.cfg" >"$work/x.out" 2>&1 || true
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
	for wc in $witnesses; do
		w=${wc%@*} c=
		[ "$w" = "$wc" ] || c=${wc#*@}
		{ consts $c; printf '    Mutant = "none"\nSPECIFICATION Spec\nINVARIANTS\n    %s\n' "$w"; } >"$work/W-$w.cfg"
		MOD=$(modof "$c") tlc "$work/W-$w.cfg" >"$work/w.out" 2>&1 || true
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
	# EvilRotate and IssueForged are mutant-only steps, never taken under
	# "none"; Lose only in EnrolLoss.cfg (MaxLost 1), Rebind only in
	# Rebind.cfg (MaxRebinds 1).
	tlc Enrol.cfg -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
	grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out"
	if grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out" | grep -v -e '^<EvilRotate' -e '^<IssueForged' -e '^<Lose' -e '^<Rebind' | grep -qE ': 0:|: 0$'; then
		echo "coverage: an action is never taken"
		return 1
	fi
	tlc EnrolLoss.cfg -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
	if grep -E '^<Lose line' "$work/cov.out" | grep -qE ': 0:|: 0$'; then
		echo "coverage: Lose is never taken in EnrolLoss.cfg"
		return 1
	fi
	tlc Rebind.cfg -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
	if grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out" | grep -v -e '^<EvilRotate' -e '^<IssueForged' -e '^<Lose' -e '^<Forge' | grep -qE ': 0:|: 0$'; then
		grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out"
		echo "coverage: an action is never taken in Rebind.cfg"
		return 1
	fi
	# InstallForged: mutant any-root only.
	tlc Join.cfg -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
	grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out"
	if grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out" | grep -v '^<InstallForged' | grep -qE ': 0:|: 0$'; then
		echo "coverage: a Join.tla action is never taken"
		return 1
	fi
	tlc RevokePush.cfg -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
	grep -E '^<[A-Z][A-Za-z]+(\(.*\))? line' "$work/cov.out"
	if grep -E '^<[A-Z][A-Za-z]+(\(.*\))? line' "$work/cov.out" | grep -qE ': 0:|: 0$'; then
		echo "coverage: a RevokePush.tla action is never taken"
		return 1
	fi
}

# trace F: accepted when every line was read with no violation.
trace() {
	t=$work/$(basename "$1")
	cat "$1" >"$t"
	[ -s "$t" ] || { echo "$1: no lines"; return 0; }
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Conforms\n    NoRenewAfterRevoke\n    OneKeyPerToken\n    NoRetiredKeyRevived\n    RefusedOnlyForCause\n    ForgedOnlyUnderStolenRoot\n    NoRenewOfRetired\n    RetiredRefused\n    RevokedMachineRefused\n    RevocationBound\n    NoExpiredSession\n    TraceDone\n' "$t" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TraceEnrol.tla) >"$t.out" 2>&1 || true
	if grep -q '^Error: Invariant TraceDone is violated' "$t.out"; then
		echo "$(basename "$1"): $(wc -l <"$t" | tr -d ' ') lines: accepted"
		return 0
	fi
	grep -m1 '^Error' "$t.out" || tail -20 "$t.out"
	echo "$(basename "$1"): $(wc -l <"$t" | tr -d ' ') lines: REJECTED"
	return 1
}

# ptrace F: a RevokePush trace (<pid>.revokepush), checked by
# TraceRevokePush.tla.
ptrace() {
	t=$work/$(basename "$1")
	cat "$1" >"$t"
	[ -s "$t" ] || { echo "$1: no lines"; return 0; }
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Known\n    ReadSeesNotice\n    PublishesRead\n    TraceDone\n' "$t" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TraceRevokePush.tla) >"$t.out" 2>&1 || true
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
	for f in $dir/traces/*.ndjson $dir/traces/*.revokepush; do
		case $f in *.revokepush) chk=ptrace ;; *) chk=trace ;; esac
		want=$(basename "$f" | cut -d- -f1)
		if $chk "$f" >"$work/m.out"; then
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
	for pkg in org/orgpki org/orgmachine org/orgenrol; do
		b=$(basename $pkg)
		(cd org && go test -tags enroltrace -c -o "$work/$b.test" ./${pkg#org/}/)
		"$work/$b.test" -test.list '^Test' >"$work/$b.tests"
		while read -r name; do
			mkdir -p "$work/unit/$b-$name"
			(cd $pkg && ENROLTRACE=$work/unit/$b-$name "$work/$b.test" -test.run "^$name\$" -test.count 1 -test.timeout 10m >"$work/unit/$b-$name.out" 2>&1) ||
				{ echo "$b $name: test failed"; tail -20 "$work/unit/$b-$name.out"; echo x >>"$work/fails"; }
		done <"$work/$b.tests"
	done
	n=0
	for f in "$work"/unit/*/*.ndjson; do
		[ -f "$f" ] || continue
		n=$((n + 1))
		trace "$f" >"$work/t.out" || { echo "$f"; cat "$work/t.out"; echo x >>"$work/fails"; }
	done
	np=0
	for f in "$work"/unit/*/*.revokepush; do
		[ -f "$f" ] || continue
		np=$((np + 1))
		ptrace "$f" >"$work/t.out" || { echo "$f"; cat "$work/t.out"; echo x >>"$work/fails"; }
	done
	echo "$np RevokePush traces"
	echo "events: $(cat "$work"/unit/*/*.ndjson 2>/dev/null | sed -E 's/.*"ev":"([a-z]+)".*/\1/' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
	echo "$n traces, $(wc -l <"$work/fails" | tr -d ' ') failed"
	fixtures || echo x >>"$work/fails"
	[ ! -s "$work/fails" ]
}

case ${1:-} in
check) run Enrol.cfg && run Rebind.cfg && run Join.cfg && run RevokePush.cfg ;;
live) run EnrolLive.cfg && run EnrolLoss.cfg ;;
mutants) mutants ;;
witnesses) witnesses ;;
coverage) coverage ;;
ci) run Enrol.cfg && run Rebind.cfg && run EnrolLive.cfg && run EnrolLoss.cfg && run Join.cfg && run RevokePush.cfg && mutants && witnesses && fixtures ;;
fixtures) fixtures ;;
traces) traces ;;
trace) trace "$2" ;;
ptrace) ptrace "$2" ;;
*) sed -n '4,20p' "$0" >&2; exit 2 ;;
esac
