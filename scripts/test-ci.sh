#!/usr/bin/env bash
# test-ci.sh: make test-race, test-linkdebug and fuzz-short one after the
# other, then one summary line each; fails if any failed (each still runs).
# In series, not at once: the three together across every package starved
# the timing-sensitive tests on a shared 10-core machine.
set -uo pipefail
cd "$(dirname "$0")/.."
failed=0
summary=""
for p in test-race test-linkdebug fuzz-short; do
	echo "── make $p"
	s=$(date +%s)
	make --no-print-directory "$p"
	rc=$?
	summary="${summary}test-ci: make $p exit $rc in $(($(date +%s) - s))s
"
	[ "$rc" -eq 0 ] || failed=1
done
printf '%s' "$summary"
exit "$failed"
