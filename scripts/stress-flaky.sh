#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# stress-flaky.sh: hammer the known-flaky tests of scripts/flaky-tests.txt
# on a starved machine, to reproduce a flake on demand on the Mac
# (`taskpolicy -b make stress-flaky`).
#
#   scripts/stress-flaky.sh [list]
#
# Each list line: <module dir> <package> <test regexp> <date seen> <run>
# (# starts a comment). The test regexp has no spaces or glob characters
# (* ? [); anchor it yourself (^TestX$, ^TestX$/^sub$). Each line runs
# through scripts/test-under-load.sh (GOMAXPROCS LOAD_GOMAXPROCS, a build
# looping beside it) with -race -count STRESS_COUNT (default 10), every
# line even after a failure. A fixed test leaves the list in its fix's
# commit. The same file in link, relay and nfltr.
# Exit status: 1 when any line failed, 2 on a malformed list.
set -u
list=${1:-scripts/flaky-tests.txt}
root=$(pwd)
[ -f "$list" ] || { echo "stress-flaky: no $list" >&2; exit 2; }
failed=() n=0
while read -r dir pkg re date run rest || [ -n "${dir:-}" ]; do
	case ${dir:-#} in \#*) continue ;; esac
	if [ -z "${run:-}" ] || [ -n "${rest:-}" ] || printf '%s' "$re" | grep -q '[*?[]'; then
		echo "stress-flaky: $list: malformed line: $dir $pkg $re ${date:-} ${run:-} ${rest:-}" >&2
		exit 2
	fi
	n=$((n + 1))
	echo "── stress-flaky: $dir $pkg -run $re (seen $date, $run) -count ${STRESS_COUNT:-10}" >&2
	start=$(date +%s)
	(cd "$dir" && LOAD_TEST_FLAGS="-race -run $re" "$root/scripts/test-under-load.sh" "${STRESS_COUNT:-10}" "$pkg")
	rc=$?
	echo "── stress-flaky: $dir $pkg $re: exit $rc in $(($(date +%s) - start))s" >&2
	[ "$rc" = 0 ] || failed+=("$dir $pkg $re")
done <"$list"
echo "stress-flaky: $n line(s), ${#failed[@]} failed" >&2
for f in ${failed[@]+"${failed[@]}"}; do echo "  FAIL $f" >&2; done
[ ${#failed[@]} = 0 ]
