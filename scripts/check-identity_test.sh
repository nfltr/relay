#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# check-identity_test.sh: scripts/check-identity.sh takes nfltr's commits
# and tags and refuses another author, committer or tagger and a
# Co-Authored-By line. Offline, in a temp repository.
set -euo pipefail
check="$(cd "$(dirname "$0")" && pwd)/check-identity.sh"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
unset "${!GIT_@}"
cd "$t"
git init -q .
ok() { GIT_AUTHOR_NAME=nfltr GIT_AUTHOR_EMAIL=oss@nfltr.xyz GIT_COMMITTER_NAME=nfltr GIT_COMMITTER_EMAIL=oss@nfltr.xyz "$@"; }
fail=0
expect() { # expect <0|1> <what> <args...>
	want=$1 what=$2
	shift 2
	if "$check" "$@" 2>/dev/null; then got=0; else got=1; fi
	[ "$got" = "$want" ] || { echo "FAIL: $what: exit $got, want $want" >&2; fail=1; }
}
ok git commit -q --allow-empty -m base
base=$(git rev-parse HEAD)
ok git commit -q --allow-empty -m good
expect 0 "nfltr's commit" HEAD "$base"
ok env GIT_AUTHOR_NAME=x GIT_AUTHOR_EMAIL=x@example.com git commit -q --allow-empty -m other-author
expect 1 "another author" HEAD "$base"
git reset -q --hard "$base"
ok git commit -q --allow-empty -m "co

Co-authored-by: Someone <s@example.com>"
expect 1 "a Co-Authored-By line" HEAD "$base"
git reset -q --hard "$base"
ok git tag -a -m v v1 HEAD
expect 0 "nfltr's tag" v1 "$base"
GIT_COMMITTER_NAME=x GIT_COMMITTER_EMAIL=x@example.com git tag -a -m v v2 HEAD
expect 1 "another tagger" v2 "$base"
git reset -q --hard "$base"
ok env GIT_COMMITTER_NAME=y GIT_COMMITTER_EMAIL=y@example.com git commit -q --allow-empty -m other-committer
expect 1 "another committer, no remote sha (all unpushed history)" HEAD 0000000000000000000000000000000000000000
[ $fail = 0 ] && echo "check-identity_test: ok"
exit $fail
