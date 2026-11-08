#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# test-under-load.sh: run Go test packages on a starved machine, so a test
# that waits a fixed time for something a busy machine does later fails
# here as it does on a loaded Mac or a busy CI runner. The fix is to wait
# for the event or state, with a bound only against a hang.
#
#   scripts/test-under-load.sh <count> <package>...
#
# The same file in link, relay and relay-core (a generic copy of nfltr's,
# which also builds nfltr's binaries). The test binaries are built first,
# unloaded. Then the tests run with GOMAXPROCS=$LOAD_GOMAXPROCS (default
# 2) while an uncached `go build -a std` loops beside them (its own
# GOCACHE, removed at the end), at background priority (macOS taskpolicy
# -b, else nice 19; LOAD_BACKGROUND=0: normal priority). LOAD_TEST_FLAGS
# adds go test flags (e.g. "-run TestX -v"); -timeout is LOAD_TIMEOUT
# (default 90m: -count multiplies a package's time, and starved it is
# several times longer).
# Exit status: go test's.
set -u
count=${1:?usage: test-under-load.sh <count> <package>...}
shift
[ $# -gt 0 ] || { echo "test-under-load: no packages" >&2; exit 2; }

work=$(mktemp -d)
load_pid=
cleanup() {
	if [ -n "$load_pid" ]; then
		kill -TERM -- "-$load_pid" 2>/dev/null || kill -TERM "$load_pid" 2>/dev/null
		wait "$load_pid" 2>/dev/null
	fi
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

go test -count=1 -run '^$' "$@" >/dev/null || exit

# The load: its own process group, so cleanup stops it and its compilers.
set -m
(
	while :; do
		GOCACHE="$work/cache" go build -a std >/dev/null 2>&1
		rm -rf "$work/cache"
	done
) &
load_pid=$!
set +m

low=()
if [ "${LOAD_BACKGROUND:-1}" = 1 ]; then
	low=(nice -n 19)
	command -v taskpolicy >/dev/null 2>&1 && low=(taskpolicy -b)
fi
echo "test-under-load: load pid $load_pid; GOMAXPROCS=${LOAD_GOMAXPROCS:-2} ${low[*]:-} go test -count=$count -timeout ${LOAD_TIMEOUT:-90m} ${LOAD_TEST_FLAGS:-} $*" >&2
# shellcheck disable=SC2086 # LOAD_TEST_FLAGS are words
GOMAXPROCS=${LOAD_GOMAXPROCS:-2} ${low[@]:+"${low[@]}"} go test -count="$count" -timeout "${LOAD_TIMEOUT:-90m}" ${LOAD_TEST_FLAGS:-} "$@"
