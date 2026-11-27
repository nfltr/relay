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
#   ci        check, mutants, witnesses, coverage, fixtures
#             (make spec-orgmove-ci); live nightly (make spec-traces).
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
#   hosted    the opt-in hosted issuer's delegation (spec/orgmove/OrgHosted.tla):
#             OrgHosted.cfg, OrgHostedLive.cfg, each line of
#             spec/orgmove/hosted-mutants.txt caught, its witnesses
#             reached, -coverage 1, hfixtures (in ci).
#   dash      the organisation in the dashboard (spec/orgmove/OrgDash.tla):
#             OrgDash.cfg, OrgDashLive.cfg, each line of
#             spec/orgmove/dash-mutants.txt caught, its witnesses reached,
#             -coverage 1 (in ci).
#   restore   a restore from a backup (OrgMove.tla Revive):
#             OrgMoveRestore.cfg, each line of
#             spec/orgmove/restore-mutants.txt caught, its witnesses
#             reached, -coverage 1; OrgMoveRestoreOlder.cfg (the relay
#             offers an older CRL) with its witness and coverage (in ci).
#   hfixtures each spec/orgmove/traces/hosted/<Invariant>-*.ndjson is
#             rejected by spec/orgmove/TraceOrgHosted.tla's <Invariant>.
#   htraces   the tests of client/orgid, org/orgmachine and orgenrol built
#             -tags enroltrace, each test's ENROLTRACE lines (the
#             verifier's) checked by TraceOrgHosted.tla; then hfixtures
#             (in traces).
#   htrace F  one trace file, by TraceOrgHosted.tla.
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
dir=spec/orgmove
spec=OrgMove
temporal="MoveCompletes"
actprops=""
mfile=mutants.txt
witnesses="WitnessMoved WitnessTokenAcrossMove WitnessRevokedAcrossMove WitnessResentAfterLoss WitnessOldWiped WitnessCrashedThenMoved WitnessBackupRefused"
# OrgMove.cfg has no restore (MaxRevive 0): Revive is covered by restore.
covskip="Revive"
cfg=""
# OrgMoveRestore.cfg: a restore from a backup (Revive) on OrgMove.tla.
restore_spec() {
	cfg=OrgMoveRestore.cfg
	mfile=restore-mutants.txt
	witnesses="WitnessRevivedTaken WitnessBehindRestored WitnessRevocationMerged WitnessTokenVoided"
	covskip="Crash" # no crash here: OrgMove.cfg covers it
}
# older: OrgMoveRestoreOlder.cfg (the relay offers a restore an older CRL
# than the fleet's: lane SECFIX2, S8), its witness, -coverage 1.
older() {
	run OrgMoveRestoreOlder.cfg
	cfg=OrgMoveRestoreOlder.cfg witnesses="WitnessOlderOffered"
	witnesses && coverage
}
# OrgHolds.tla: its actions taken only under a mutant (coverage skips them).
holds_spec() {
	spec=OrgHolds
	actprops="HolderKeeps"
	mfile=holds-mutants.txt
	witnesses="WitnessMoved WitnessMovedBack WitnessBackUnpublished WitnessTakenVacant WitnessLateWrite WitnessFinished WitnessReturnToFinished WitnessReadFirst"
	covskip="EarlyRelease|XRelease"
}
# OrgHosted.tla: SelfRenew and AutoActivate are taken only under a mutant.
hosted_spec() {
	spec=OrgHosted
	actprops=""
	temporal="RevokeTakesEffect"
	mfile=hosted-mutants.txt
	witnesses="WitnessHostedServes WitnessMovedOff WitnessStolenSession WitnessRevokedCut WitnessOwnerActivated WitnessRenewed WitnessRevokedRemoteRenewal WitnessResigned"
	covskip="SelfRenew|AutoActivate"
}

# OrgDash.tla: WishRevoke and WishRenew are taken only under a mutant.
dash_spec() {
	spec=OrgDash
	actprops=""
	temporal="RevokeTakesEffect RenewCompletes"
	mfile=dash-mutants.txt
	witnesses="WitnessRevokedFromDashboard WitnessRenewed WitnessForgedRefused WitnessReplayShown WitnessStaleOrderRefused WitnessRelayWishDeclined WitnessSecondOrgRefused WitnessGroupMismatch"
	covskip="WishRevoke|WishRenew"
	cfg=""
}

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
consts() { sed -n '/^CONSTANTS/,/^SPECIFICATION/p' $dir/${1:-${cfg:-$spec.cfg}} | grep -v -e Mutant -e '^SPECIFICATION'; }

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
	tlc ${cfg:-$spec.cfg} -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
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

# htrace F: a verifier trace (orgid's, ENROLTRACE) by TraceOrgHosted.tla.
htrace() {
	t=$work/h-$(basename "$1")
	cat "$1" >"$t"
	[ -s "$t" ] || { echo "$1: no lines"; return 0; }
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Conforms\n    RevokedIssuerRefused\n    DelegationBound\n    TraceDone\n' "$t" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TraceOrgHosted.tla) >"$t.out" 2>&1 || true
	if grep -q '^Error: Invariant TraceDone is violated' "$t.out"; then
		echo "$(basename "$1"): $(wc -l <"$t" | tr -d ' ') lines: accepted"
		return 0
	fi
	grep -m1 '^Error' "$t.out" || tail -20 "$t.out"
	echo "$(basename "$1"): $(wc -l <"$t" | tr -d ' ') lines: REJECTED"
	return 1
}

# fixtures [hosted]: each fixture rejected by its invariant (TraceOrgMove.tla,
# or with hosted TraceOrgHosted.tla's of traces/hosted).
# otrace F ORG: organisation ORG's issuer steps in F (<pid>.holds),
# checked by TraceOrgHolds.tla; 0 when accepted.
otrace() {
	t=$work/$(basename "$1").$2
	cat "$1" >"$t"
	printf 'CONSTANTS\n    TraceFile = "%s"\n    Org = "%s"\n    MaxMoves = 3\n    MaxBad = 0\n    Mutant = "none"\nINIT TraceInit\nNEXT TraceNext\nINVARIANTS\n    TypeOK\n    OldCannotWrite\n    RootReadable\n    FinishAfterPublish\n    TraceNotDone\n' "$t" "$2" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TraceOrgHolds.tla) >"$t.out" 2>&1 || true
	if grep -q '^Error: Invariant TraceNotDone is violated' "$t.out"; then
		echo "$(basename "$1") $2: $(grep -c "\"o\":\"$2\"" "$t") lines: accepted"
		return 0
	fi
	grep -m1 '^Error' "$t.out" || tail -20 "$t.out"
	echo "$(basename "$1") $2: REJECTED"
	return 1
}

# otraces F: each organisation of F with at most two issuer directories
# (OrgHolds.tla's A and B; more is a restore from a backup, OrgMove.tla
# Revive, or a second move elsewhere, outside the model: skipped, named).
otraces() {
	fail=0
	# A lock line names its directory only: one no organisation served
	# (a restore's backup, the move run on it) counts for each.
	sed -nE 's/.*"d":"([^"]+)".*"o":"[^"]+".*/\1/p' "$1" | sort -u >"$work/odirs"
	sed -nE 's/.*"d":"([^"]+)","ev":"lock".*/\1/p' "$1" | sort -u | comm -23 - "$work/odirs" >"$work/ldirs"
	for o in $(sed -nE 's/.*"o":"([^"]+)".*/\1/p' "$1" | sort -u); do
		nd=$( (grep "\"o\":\"$o\"" "$1" | sed -nE 's/.*"d":"([^"]+)".*/\1/p'; cat "$work/ldirs") | sort -u | wc -l | tr -d ' ')
		if [ "$nd" -gt 2 ]; then
			echo "$(basename "$1") $o: $nd directories: skipped"
			continue
		fi
		otrace "$1" "$o" || fail=1
	done
	return $fail
}

# ofixtures: each traces/holds/<Invariant>-*.holds (organisation "O") is
# no behaviour of OrgHolds.tla (a mutant's run), each Accepted-*.holds one.
ofixtures() {
	: >"$work/ofails"
	for f in $dir/traces/holds/*.holds; do
		if otrace "$f" O >"$work/m.out"; then
			case $(basename "$f") in Accepted-*) echo "$(basename "$f"): accepted" ;; *) echo "$(basename "$f"): NOT rejected"; echo x >>"$work/ofails" ;; esac
		else
			case $(basename "$f") in Accepted-*) echo "$(basename "$f"): NOT accepted"; echo x >>"$work/ofails" ;; *) echo "$(basename "$f"): rejected" ;; esac
		fi
	done
	[ ! -s "$work/ofails" ]
}

fixtures() {
	: >"$work/ffails"
	sub= chk=trace
	[ "${1:-}" = hosted ] && sub=/hosted chk=htrace
	for f in $dir/traces$sub/*.ndjson; do
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
	# OrgHolds.tla: orgenrol's issuer steps (<pid>.holds); a step no
	# trace takes is a test gap.
	no=0
	for f in "$work"/unit/*/*.holds; do
		[ -f "$f" ] || continue
		no=$((no + 1))
		otraces "$f" >"$work/t.out" || { echo "$f"; cat "$work/t.out"; echo x >>"$work/fails"; }
		grep skipped "$work/t.out" || true
	done
	cat "$work"/unit/*/*.holds 2>/dev/null | sed -E 's/.*"ev":"write","n":0.*/write-none/; s/.*"ev":"([a-z]+)".*/\1/' | sort | uniq -c >"$work/ocov"
	echo "$no OrgHolds traces: $(tr -s ' ' <"$work/ocov" | tr '\n' ' ')"
	for want in start read write write-none stop exit lock release; do
		grep -q " $want\$" "$work/ocov" || { echo "coverage: no OrgHolds trace takes $want"; echo x >>"$work/fails"; }
	done
	ofixtures || echo x >>"$work/fails"
	htraces || echo x >>"$work/fails"
	[ ! -s "$work/fails" ]
}

# htraces: the verifier's lines of client/orgid's, orgmachine's and
# orgenrol's tests (orgid writes them under ENROLTRACE), by
# TraceOrgHosted.tla; then the hosted fixtures.
htraces() {
	: >"$work/hfails"
	for pkg in client/orgid org/orgmachine org/orgenrol; do
		b=h$(basename $pkg)
		m=${pkg%%/*}
		(cd $m && go test -tags enroltrace -c -o "$work/$b.test" ./${pkg#*/}/)
		"$work/$b.test" -test.list '^Test' >"$work/$b.tests"
		while read -r name; do
			mkdir -p "$work/hunit/$b-$name"
			(cd $pkg && ENROLTRACE=$work/hunit/$b-$name "$work/$b.test" -test.run "^$name\$" -test.count 1 -test.timeout 10m >"$work/hunit/$b-$name.out" 2>&1) ||
				{ echo "$b $name: test failed"; tail -20 "$work/hunit/$b-$name.out"; echo x >>"$work/hfails"; }
		done <"$work/$b.tests"
	done
	n=0
	for f in "$work"/hunit/*/*.ndjson; do
		[ -f "$f" ] || continue
		grep -qE '"ev":"(itake|check)"' "$f" || continue
		n=$((n + 1))
		htrace "$f" >"$work/t.out" || { echo "$f"; cat "$work/t.out"; echo x >>"$work/hfails"; }
	done
	echo "hosted events: $(cat "$work"/hunit/*/*.ndjson 2>/dev/null | grep -o '"ev":"[a-z]*"' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
	echo "$n verifier traces, $(wc -l <"$work/hfails" | tr -d ' ') failed"
	fixtures hosted || echo x >>"$work/hfails"
	[ ! -s "$work/hfails" ]
}

case ${1:-} in
check) run OrgMove.cfg ;;
live) run OrgMoveLive.cfg ;;
repeat) run OrgMoveRepeat.cfg ;;
mutants) mutants ;;
witnesses) witnesses ;;
coverage) coverage ;;
# ci: each model's coverage run is its invariants' check too (the same
# config, -coverage 1, failing on a violation), so ci runs it once.
# OrgMoveLive.cfg's pass (MoveCompletes, about 6 minutes) is nightly (live,
# make spec-traces); its mutants run here (lane SPECFAST).
ci) mutants && witnesses && coverage && fixtures && ofixtures &&
	holds_spec && run OrgHoldsLive.cfg && mutants && witnesses && coverage &&
	hosted_spec && run OrgHostedLive.cfg && mutants && witnesses && coverage && fixtures hosted &&
	dash_spec && run OrgDashLive.cfg && mutants && witnesses && coverage &&
	spec=OrgMove && restore_spec && mutants && witnesses && coverage ;;
dash) dash_spec && run OrgDash.cfg && run OrgDashLive.cfg && mutants && witnesses && coverage ;;
restore) restore_spec && run OrgMoveRestore.cfg && mutants && witnesses && coverage && older ;;
hosted) hosted_spec && run OrgHosted.cfg && run OrgHostedLive.cfg && mutants && witnesses && coverage && fixtures hosted ;;
hfixtures) fixtures hosted ;;
htraces) htraces ;;
htrace) htrace "$2" ;;
holds) holds_spec && run OrgHolds.cfg && run OrgHoldsLive.cfg && mutants && witnesses && coverage ;;
fixtures) fixtures ;;
traces) traces ;;
trace) trace "$2" ;;
*) sed -n '4,40p' "$0" >&2; exit 2 ;;
esac
