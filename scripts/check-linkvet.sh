#!/usr/bin/env bash
# check-linkvet.sh [packages...]: linkvet (github.com/nfltr/link/linkvet, the
# version pinned below) over this repository's non-test code. Fails on a
# finding scripts/linkvet-allow.txt does not list and on an allow entry no
# finding matches (stale). Packages default to ./... from the repository root.
# linkvet is installed at its tag into a temp dir, so golang.org/x/tools never
# enters this repository's go.mod; offline once it is in the module cache.
set -euo pipefail
cd "$(dirname "$0")/.."
LINKVET_VERSION=v0.1.1
allow=scripts/linkvet-allow.txt
[ $# -gt 0 ] || set -- ./...

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
GOFLAGS= GOWORK=off GOBIN="$tmp" \
	go install "github.com/nfltr/link/linkvet/cmd/linkvet@$LINKVET_VERSION"

rc=0
"$tmp/linkvet" -test=false "$@" >"$tmp/out" 2>&1 || rc=$?
# 3: findings were reported; anything else non-zero: linkvet itself failed.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
	cat "$tmp/out" >&2
	echo "check-linkvet: linkvet exited $rc" >&2
	exit "$rc"
fi
# A finding's key: its path from the repository root and its message, without
# line and column (an entry survives edits elsewhere in the file).
root=$(pwd -P)
grep -E '^[^ ]+:[0-9]+:[0-9]+: ' "$tmp/out" | sed -e "s|^$root/||" -e 's|:[0-9]*:[0-9]*: |: |' | sort -u >"$tmp/found" || true

# An allow entry: "<path>: <message> -- <reason>"; # starts a comment line.
: >"$tmp/allowed"
if [ -f "$allow" ]; then
	bad=$(grep -v -e '^#' -e '^[[:space:]]*$' "$allow" | grep -v -e ' -- [^ ]' || true)
	if [ -n "$bad" ]; then
		printf 'check-linkvet: %s entry without " -- <reason>":\n%s\n' "$allow" "$bad" >&2
		exit 1
	fi
	grep -v -e '^#' -e '^[[:space:]]*$' "$allow" | sed 's/ -- .*//' | sort -u >"$tmp/allowed" || true
fi

fail=0
new=$(comm -23 "$tmp/found" "$tmp/allowed")
stale=$(comm -13 "$tmp/found" "$tmp/allowed")
if [ -n "$new" ]; then
	grep -E '^[^ ]+:[0-9]+:[0-9]+: ' "$tmp/out" | sed "s|^$root/||" >&2
	printf 'check-linkvet: findings not in %s (fix them, or add "<path>: <message> -- <reason>"):\n%s\n' "$allow" "$new" >&2
	fail=1
fi
if [ -n "$stale" ]; then
	printf 'check-linkvet: stale %s entries (no finding matches; remove them):\n%s\n' "$allow" "$stale" >&2
	fail=1
fi
[ "$fail" -eq 0 ] && echo "check-linkvet: linkvet $LINKVET_VERSION, $(wc -l <"$tmp/found" | tr -d ' ') finding(s), all allow-listed"
exit "$fail"
