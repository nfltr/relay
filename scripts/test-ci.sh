#!/usr/bin/env bash
# test-ci.sh: make test-race alone, then make test-linkdebug and fuzz-short
# at once (each to its own log, printed in that order once both ended), then
# one summary line each; fails if any failed (each still runs).
# The race pass runs alone: race, linkdebug and fuzzing together across
# every package starved the timing-sensitive tests on a shared 10-core
# machine.
# Fuzzing beside the linkdebug pass gets half the CPUs (FUZZPARALLEL), so
# the linkdebug tests keep the other half; its wall is FUZZTIME per target
# either way.
set -uo pipefail
cd "$(dirname "$0")/.."
summary=""
failed=0
echo "── make test-race"
s=$(date +%s)
make --no-print-directory test-race
rc=$?
summary="test-ci: make test-race exit $rc in $(($(date +%s) - s))s
"
[ "$rc" -eq 0 ] || failed=1

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
half=$((($(getconf _NPROCESSORS_ONLN) + 1) / 2))
parts="test-linkdebug fuzz-short"
for p in $parts; do
	(
		s=$(date +%s)
		FUZZPARALLEL="${FUZZPARALLEL:-$half}" make --no-print-directory "$p" >"$dir/$p.log" 2>&1
		echo "$? $(($(date +%s) - s))" >"$dir/$p.rc"
	) &
done
wait
for p in $parts; do
	read -r rc secs <"$dir/$p.rc"
	echo "── make $p"
	cat "$dir/$p.log"
	summary="${summary}test-ci: make $p exit $rc in ${secs}s
"
	[ "$rc" -eq 0 ] || failed=1
done
printf '%s' "$summary"
exit "$failed"
