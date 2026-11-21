#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

# check-api_test.sh: scripts/check-api.sh in clones of a fixture module whose
# HEAD adds a func to its v0.1.0 API. A clone with the tags compares against
# v0.1.0 (the unlisted change fails it); a clone without the tags, or a
# shallow one, never passes: the box's depth-1 relay-server clone once passed
# by comparing nothing (lane APITAGS). CHECK_API=<script> tests another copy.
# The same file in link, relay, relay-core and relay-server.
set -eu
script=${CHECK_API:-$(cd "$(dirname "$0")" && pwd)/check-api.sh}
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "check-api_test: $*" >&2; exit 1; }
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY
export GOWORK=off GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$t/gitconfig"
git config --global user.name check-api-test
git config --global user.email test@invalid

o=$t/origin
git init -q "$o"
mkdir "$o/scripts"
cp "$script" "$o/scripts/check-api.sh"
printf 'module example.com/m\n\ngo 1.21\n' >"$o/go.mod"
printf 'package m\n\nfunc A() {}\n' >"$o/m.go"
git -C "$o" add -A && git -C "$o" commit -qm v0.1.0 && git -C "$o" tag v0.1.0
printf 'func B() {}\n' >>"$o/m.go"
git -C "$o" commit -qam 'add B'

# run <clone flags...>: check-api in a fresh clone, its status and output.
run() {
	rm -rf "$t/c"
	git clone -q "$@" "file://$o" "$t/c"
	set +e
	(cd "$t/c" && ./scripts/check-api.sh . '' m) >"$t/out" 2>&1
	rc=$?
	set -e
}

run
[ $rc -ne 0 ] && grep -q 'changed since v0.1.0' "$t/out" ||
	fail "with tags: want a comparison against v0.1.0 that fails on the unlisted B, got status $rc: $(cat "$t/out")"
for flags in --no-tags '--depth 1'; do
	run $flags
	[ $rc -ne 0 ] || fail "clone $flags: passed without comparing: $(cat "$t/out")"
	grep -q 'no release tag\|changed since v0.1.0' "$t/out" ||
		fail "clone $flags: want 'no release tag' (or a real comparison), got: $(cat "$t/out")"
done
echo "check-api_test: ok"
