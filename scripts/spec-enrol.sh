#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# spec-enrol.sh ci|check|live|mutants|witnesses|coverage|fixtures|traces|trace F: the TLA+ model of
# organisation certificates' lifecycle: renewal, revocation, root rotation
# (spec/enrol/README.md).
#   check     TLC on spec/enrol/Enrol.cfg: every invariant; Rebind.cfg:
#             the same with a rebind; Join.cfg: the
#             join by token (Join.tla); RevokePush.cfg: a revoke's events
#             and backstops (RevokePush.tla); CrlCarriers.cfg: the CRL on
#             the mailbox and the relay's copy (CrlCarriers.tla);
#             CrlCarriersReplicas.cfg: the same on two replicas;
#             CertRide.cfg: a machine certificate through issuer
#             outages (CertRide.tla); CertRideHost.cfg: the SSH host
#             certificate of a revoked machine; CertRideDay.cfg: the same
#             with the 24 h machine certificate of step A.
#   live      TLC on spec/enrol/EnrolLive.cfg: the temporal properties;
#             EnrolLoss.cfg: everything with the relay losing messages.
#   mutants   each line of spec/enrol/mutants.txt must be caught (a line
#             naming a Join*.cfg runs Join.tla).
#   witnesses each Witness* must be violated (reachable).
#   ci        check (CrlCarriersReplicas.cfg aside: its mutants and
#             witness only), EnrolLoss.cfg's invariants, mutants (the
#             temporal ones on LiveSpec), witnesses, fixtures (make
#             spec-enrol-ci); live's full liveness runs nightly
#             (spec-traces).
#   replicas  CrlCarriersReplicas.cfg (15M states, about half under its
#             symmetry; nightly in make spec-traces).
#   coverage  check with -coverage 1; fails on an action never taken.
#   fixtures  each spec/enrol/traces/<Invariant>-*.ndjson is rejected by
#             <Invariant> of TraceEnrol.tla, each Accepted-*.ndjson accepted
#             (in ci).
#   traces    the tests of org/orgpki, orgmachine and orgenrol built -tags
#             enroltrace, each test's trace checked by TraceEnrol.tla, then
#             the fixtures (make spec-enrol-traces).
#   trace F   one recorded trace file; ptrace F one RevokePush trace
#             (<pid>.revokepush, TraceRevokePush.tla); ctrace F one
#             CrlCarriers trace (<pid>.crlcarriers, TraceCrlCarriers.tla;
#             traces also runs client/orgid's Follow tests for these).
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
dir=spec/enrol
temporal="TakesEffect MachinesFollowRotation RenewsAfterExpiry"
witnesses="WitnessRenewed WitnessRenewedAfterExpiry WitnessRevokeSeen WitnessFailClosed WitnessForgedSession WitnessRotated WitnessSessionAfterRotation WitnessRetried@EnrolLoss.cfg WitnessAnsweredAgain@EnrolLoss.cfg WitnessRebound@Rebind.cfg WitnessSessionAfterRebind@Rebind.cfg WitnessRetiredHeld@Rebind.cfg WitnessMoved@Rebind.cfg WitnessReissuedOwnId@Rebind.cfg
WitnessRetriedJoin@Join.cfg WitnessReissued@Join.cfg WitnessJoinedAfterLoss@Join.cfg WitnessJoinedAfterRotation@Join.cfg WitnessRefusedOther@Join.cfg WitnessRefusedEvil@Join.cfg WitnessRefusedOlder@JoinOlder.cfg WitnessJoinedBound@Join.cfg WitnessRefusedRelabeled@Join.cfg
WitnessCutByPush@RevokePush.cfg WitnessServeBackstop@RevokePush.cfg WitnessFollowBackstop@RevokePush.cfg WitnessHeldAfterRevoke@RevokePush.cfg
WitnessLapsed@CrlCarriers.cfg WitnessCopyWhileMailboxDown@CrlCarriers.cfg WitnessAlert@CrlCarriers.cfg WitnessLearned@CrlCarriers.cfg WitnessRestartWhileIssuerDown@CrlCarriers.cfg
WitnessAlertWithoutCopy@CrlCarriers.cfg WitnessPeerCopy@CrlCarriersReplicas.cfg
WitnessRodeOutage@CrlCarriers.cfg WitnessWarned@CrlCarriers.cfg WitnessRevokedPastPush@CrlCarriers.cfg
WitnessRodeOutage@CertRide.cfg WitnessLapsed@CertRide.cfg WitnessRenewedLate@CertRide.cfg WitnessHostLapsed@CertRide.cfg WitnessHostTrustedAfterRevoke@CertRideHost.cfg WitnessHostTrustedAfterRevoke@CertRideDay.cfg"

# modof CFG: the module a config checks (Join*.cfg: Join.tla,
# RevokePush*.cfg: RevokePush.tla, CrlCarriers*.cfg: CrlCarriers.tla,
# CertRide*.cfg: CertRide.tla).
modof() { case ${1:-} in Join*) echo Join ;; RevokePush*) echo RevokePush ;; CrlCarriers*) echo CrlCarriers ;; CertRide*) echo CertRide ;; *) echo Enrol ;; esac; }

tlc() {
	cfg_=$1
	shift
	(cd $dir && "$cicache" tlc -- "$java" -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "${TLC_WORKERS:-2}" \
		-noGenerateSpecTE -deadlock -metadir "$work/states-$(basename "$cfg_")" -config "$cfg_" "$@" "${MOD:-$(modof "$cfg_")}.tla")
}

run() {
	o=$work/c-${1##*/}.out
	if ! tlc "$1" >"$o" 2>&1; then
		tail -40 "$o"
		echo "$1: FAILED"
		return 1
	fi
	echo "${1##*/}: ok ($(grep -m1 'distinct states found, 0 states left' "$o" | sed 's/.* generated, //; s/, 0 states left.*//'), $(grep -m1 'Finished in' "$o" | sed 's/ at .*//'))"
}

# invariants CFG: CFG's invariants alone (Spec, no PROPERTIES).
invariants() {
	sed -e 's/^SPECIFICATION LiveSpec/SPECIFICATION Spec/' -e '/^PROPERTIES/,/^INVARIANTS/{/^INVARIANTS/!d;}' $dir/$1 >"$work/inv-$1"
	run "$work/inv-$1"
}

# consts [cfg]: a config's constants (Enrol.cfg's by default), Mutant aside.
consts() { sed -n '/^CONSTANTS/,/^SPECIFICATION/p' $dir/${1:-Enrol.cfg} | grep -v -e Mutant -e '^SPECIFICATION'; }

# mutant1 M P WANT MOD: one mutant, caught when its TLC output matches WANT (a pool check).
mutant1() {
	MOD=$4 tlc "$work/X-$1-$2.cfg" >"$work/x-$1-$2.out" 2>&1 || true
	if grep -Eq "$3" "$work/x-$1-$2.out"; then
		echo "$1: caught by $2 ($(grep -c '^State [0-9]*:' "$work/x-$1-$2.out") states deep)"
	else
		echo "$1: NOT caught by $2"
		grep -m3 -E '^Error' "$work/x-$1-$2.out" || true
		return 1
	fi
}

mutants() {
	grep -v '^#' $dir/mutants.txt >"$work/mlist"
	pool_start "$work/pool"
	while read -r m p c; do
		[ -n "$m" ] || continue
		case " $temporal " in
		*" $p "*) { consts $c; printf '    Mutant = "%s"\nSPECIFICATION LiveSpec\nPROPERTIES\n    %s\n' "$m" "$p"; } >"$work/X-$m-$p.cfg"
			want="^Error: Temporal propert(y|ies) .*violated" ;;
		*) { consts $c; printf '    Mutant = "%s"\nSPECIFICATION Spec\nINVARIANTS\n    TypeOK\n    %s\n' "$m" "$p"; } >"$work/X-$m-$p.cfg"
			want="^Error: Invariant $p is violated" ;;
		esac
		pool mutant1 "$m" "$p" "$want" "$(modof "$c")"
	done <"$work/mlist"
	pool_end
}

# witness1 W MOD ID: the witness W reached (violated; a pool check). ID
# (W and its configuration) names its files: a witness name recurs in
# several configurations, which the pool checks at once.
witness1() {
	MOD=$2 tlc "$work/W-$3.cfg" >"$work/w-$3.out" 2>&1 || true
	if grep -q "^Error: Invariant $1 is violated" "$work/w-$3.out"; then
		echo "$1: reached"
	else
		echo "$1: NOT reached"
		return 1
	fi
}

witnesses() {
	pool_start "$work/pool"
	for wc in $witnesses; do
		w=${wc%@*} c=
		[ "$w" = "$wc" ] || c=${wc#*@}
		id=$w${c:+-${c%.cfg}}
		{ consts $c; printf '    Mutant = "none"\nSPECIFICATION Spec\nINVARIANTS\n    %s\n' "$w"; } >"$work/W-$id.cfg"
		pool witness1 "$w" "$(modof "$c")" "$id"
	done
	pool_end
}

coverage() {
	# EvilRotate and IssueForged are mutant-only steps, never taken under
	# "none"; Lose only in EnrolLoss.cfg (MaxLost 1), Rebind and Move only
	# in Rebind.cfg (MaxRebinds 1).
	tlc Enrol.cfg -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
	grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out"
	if grep -E '^<[A-Za-z]+(\(.*\))? line' "$work/cov.out" | grep -v -e '^<EvilRotate' -e '^<IssueForged' -e '^<Lose' -e '^<Rebind' -e '^<Move' | grep -qE ': 0:|: 0$'; then
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
	# ServeForged: mutant copy-unsigned only; Deliver needs a second
	# replica (CrlCarriersReplicas.cfg).
	for c in CrlCarriers.cfg CrlCarriersReplicas.cfg; do
		tlc $c -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
		grep -E '^<[A-Z][A-Za-z]+(\(.*\))? line' "$work/cov.out"
		skip='^<ServeForged'
		[ $c = CrlCarriersReplicas.cfg ] || skip='^<ServeForged|^<Deliver'
		if grep -E '^<[A-Z][A-Za-z]+(\(.*\))? line' "$work/cov.out" | grep -vE "$skip" | grep -qE ': 0:|: 0$'; then
			echo "coverage: a CrlCarriers.tla action is never taken ($c)"
			return 1
		fi
	done
	# Revoke: CertRideHost.cfg only (Revokes FALSE in CertRide.cfg).
	for c in CertRide.cfg CertRideHost.cfg CertRideDay.cfg; do
		tlc $c -coverage 1 >"$work/cov.out" 2>&1 || { tail -20 "$work/cov.out"; return 1; }
		grep -E '^<[A-Z][A-Za-z]+(\(.*\))? line' "$work/cov.out"
		skip='^<Revoke'
		[ $c = CertRide.cfg ] || skip='^<none'
		if grep -E '^<[A-Z][A-Za-z]+(\(.*\))? line' "$work/cov.out" | grep -vE "$skip" | grep -qE ': 0:|: 0$'; then
			echo "coverage: a CertRide.tla action is never taken ($c)"
			return 1
		fi
	done
}

# trace F: accepted when every line was read with no violation.
trace() {
	t=$work/$(basename "$1")
	cat "$1" >"$t"
	[ -s "$t" ] || { echo "$1: no lines"; return 0; }
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Conforms\n    NoRenewAfterRevoke\n    OneKeyPerToken\n    NoRetiredKeyRevived\n    RefusedOnlyForCause\n    ForgedOnlyUnderStolenRoot\n    NoRenewOfRetired\n    RetiredRefused\n    ReissueRetiresOnlyExpired\n    RevokedMachineRefused\n    RevocationBound\n    NoExpiredSession\n    NoRenewPastGrace\n    GraceOnlyNewest\n    TraceDone\n' "$t" >"$t.cfg"
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

# jtrace F: the join's lines of F (orgenrol's, beside the issuer's),
# checked by TraceJoin.tla.
jtrace() {
	t=$work/$(basename "$1").j
	cat "$1" >"$t"
	[ -s "$t" ] || { echo "$1: no lines"; return 0; }
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Conforms\n    RefusedOnlyForCause\n    JoinRootsAreOwners\n    TraceDone\n' "$t" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TraceJoin.tla) >"$t.out" 2>&1 || true
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

# ctrace F: a CrlCarriers trace (<pid>.crlcarriers: the issuer's puts and
# publishes, members' takes with their carrier), checked by
# TraceCrlCarriers.tla.
ctrace() {
	t=$work/$(basename "$1")
	cat "$1" >"$t"
	[ -s "$t" ] || { echo "$1: no lines"; return 0; }
	printf 'CONSTANTS\n    TraceFile = "%s"\nINIT Init\nNEXT Next\nINVARIANTS\n    Known\n    RevocationBound\n    RevokedMachineRefused\n    PutBeforePublish\n    TraceDone\n' "$t" >"$t.cfg"
	(cd $dir && "$java" -cp "$jar" tlc2.TLC -workers 1 -noGenerateSpecTE -deadlock \
		-metadir "$t.states" -config "$t.cfg" TraceCrlCarriers.tla) >"$t.out" 2>&1 || true
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
	for f in $dir/traces/*.ndjson $dir/traces/*.revokepush $dir/traces/*.crlcarriers $dir/traces/*.join; do
		case $f in *.revokepush) chk=ptrace ;; *.crlcarriers) chk=ctrace ;; *.join) chk=jtrace ;; *) chk=trace ;; esac
		want=$(basename "$f" | cut -d- -f1)
		if [ "$want" = Accepted ]; then
			if $chk "$f" >"$work/m.out"; then
				echo "$(basename "$f"): accepted"
			else
				echo "$(basename "$f"): NOT accepted: $(grep -m1 '^Error' "$work/m.out")"
				echo x >>"$work/ffails"
			fi
			continue
		fi
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
	# Join.tla's machine side: every trace with a join's lines, and the
	# outcomes they take (a step no test takes is a test gap).
	nj=0
	for f in "$work"/unit/*/*.ndjson; do
		grep -q '"ev":"j' "$f" || continue
		nj=$((nj + 1))
		jtrace "$f" >"$work/t.out" || { echo "$f"; cat "$work/t.out"; echo x >>"$work/fails"; }
	done
	cat "$work"/unit/*/*.ndjson 2>/dev/null | grep '"ev":"j' |
		sed -E 's/.*"ev":"jroot".*"ok":(true|false).*"own":(true|false).*/jroot-ok-\1-own-\2/; s/.*"ev":"jend".*"res":"([a-z]+)".*/jend-\1/; s/.*"ev":"jstart".*/jstart/' |
		sort | uniq -c >"$work/jcov"
	# A run again with the kept key: a jstart whose first is not its run.
	n2=$(cat "$work"/unit/*/*.ndjson 2>/dev/null | grep '"ev":"jstart"' | grep -cvE '"first":"([^"]*)".*"run":"\1"' || true)
	echo "$nj Join traces: $(tr -s ' ' <"$work/jcov" | tr '\n' ' ') jstart-again $n2"
	for want in jroot-ok-true-own-true jroot-ok-false-own-false jend-joined jend-refused jend-failed; do
		grep -q " $want\$" "$work/jcov" || { echo "coverage: no Join trace takes $want"; echo x >>"$work/fails"; }
	done
	[ "$n2" -gt 0 ] || { echo "coverage: no Join trace runs a join again"; echo x >>"$work/fails"; }
	np=0
	for f in "$work"/unit/*/*.revokepush; do
		[ -f "$f" ] || continue
		np=$((np + 1))
		ptrace "$f" >"$work/t.out" || { echo "$f"; cat "$work/t.out"; echo x >>"$work/fails"; }
	done
	echo "$np RevokePush traces"
	# CrlCarriers: also relay client orgid's Follow tests (only their
	# carrier lines: the verifier's own lines are TraceEnrol's above).
	(cd client && go test -tags enroltrace -c -o "$work/orgid.test" ./orgid/)
	"$work/orgid.test" -test.list '^TestFollow' >"$work/orgid.tests"
	while read -r name; do
		mkdir -p "$work/carry/orgid-$name"
		(cd client/orgid && ENROLTRACE=$work/carry/orgid-$name "$work/orgid.test" -test.run "^$name\$" -test.count 1 -test.timeout 10m >"$work/carry/orgid-$name.out" 2>&1) ||
			{ echo "orgid $name: test failed"; tail -20 "$work/carry/orgid-$name.out"; echo x >>"$work/fails"; }
	done <"$work/orgid.tests"
	nc=0
	for f in "$work"/unit/*/*.crlcarriers "$work"/carry/*/*.crlcarriers; do
		[ -f "$f" ] || continue
		nc=$((nc + 1))
		ctrace "$f" >"$work/t.out" || { echo "$f"; cat "$work/t.out"; echo x >>"$work/fails"; }
	done
	# Coverage: each CrlCarriers step some trace takes (PutCopy, Publish,
	# Push, ReadCopy); a step no test takes is a test gap.
	cat "$work"/unit/*/*.crlcarriers "$work"/carry/*/*.crlcarriers 2>/dev/null |
		sed -E 's/.*"ev":"([a-z]+)".*/\1/; s/^take$//' | grep . | sort | uniq -c >"$work/ccov"
	cat "$work"/unit/*/*.crlcarriers "$work"/carry/*/*.crlcarriers 2>/dev/null | grep '"ev":"take"' |
		sed -E 's/.*"res":"([a-z]+)".*"via":"([a-z]+)".*|.*"via":"([a-z]+)".*"res":"([a-z]+)".*/take-\2\3-\1\4/' | sort | uniq -c >>"$work/ccov"
	echo "$nc CrlCarriers traces: $(tr -s ' ' <"$work/ccov" | tr '\n' ' ')"
	for want in put publish take-mailbox-taken take-copy-taken take-copy-refused; do
		grep -q " $want\$" "$work/ccov" || { echo "coverage: no CrlCarriers trace takes $want"; echo x >>"$work/fails"; }
	done
	echo "events: $(cat "$work"/unit/*/*.ndjson 2>/dev/null | sed -E 's/.*"ev":"([a-z]+)".*/\1/' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')"
	echo "$n traces, $(wc -l <"$work/fails" | tr -d ' ') failed"
	fixtures || echo x >>"$work/fails"
	[ ! -s "$work/fails" ]
}

case ${1:-} in
check) run Enrol.cfg && run Rebind.cfg && run Join.cfg && run JoinOlder.cfg && run RevokePush.cfg && run CrlCarriers.cfg && run CrlCarriersReplicas.cfg && run CertRide.cfg && run CertRideHost.cfg && run CertRideDay.cfg ;;
live) run EnrolLive.cfg && run EnrolLoss.cfg ;;
mutants) mutants ;;
witnesses) witnesses ;;
coverage) coverage ;;
ci)
	# The mutants' pool and CrlCarriers.cfg (the longest, about 12
	# minutes) beside the other configurations (lane SPECFAST: it ran after
	# them).
	(mutants) >"$work/mutants.out" 2>&1 &
	mp=$!
	(run CrlCarriers.cfg) >"$work/crl.out" 2>&1 &
	cp=$!
	st=0
	run Enrol.cfg && run Rebind.cfg && invariants EnrolLoss.cfg && run Join.cfg && run JoinOlder.cfg && run RevokePush.cfg && run CertRide.cfg && run CertRideHost.cfg && run CertRideDay.cfg || st=1
	wait $cp || st=1
	cat "$work/crl.out"
	wait $mp || st=1
	cat "$work/mutants.out"
	[ $st = 0 ] && witnesses && fixtures ;;
fixtures) fixtures ;;
traces) traces ;;
replicas) run CrlCarriersReplicas.cfg ;;
trace) trace "$2" ;;
ptrace) ptrace "$2" ;;
ctrace) ctrace "$2" ;;
*) sed -n '4,20p' "$0" >&2; exit 2 ;;
esac
