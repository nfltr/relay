#!/usr/bin/env bash
# test-linkdebug.sh [module dirs...]: link's debug mode (-tags linkdebug,
# github.com/nfltr/link README "Finding misuse: linkvet and debug mode") on
# this repository: go vet with the tag over every package, then the tests of
# every package that imports link with the tag. Link prints its reports (a
# session never closed, concurrent Reads or Writes on one session) on
# stderr and fails nothing, and go test hides a passing package's stderr:
# each such package's TestMain is leakcheck's, which, built with the tag,
# fails the package on a report. A package without it fails this script.
# No -race: the debug mode's per-session lock orders Reads (Writes) from
# different goroutines, so under it the race detector misses a session
# read by two goroutines one after the other with nothing ordering them;
# make test-race runs those packages without the tag. Module dirs default to the
# repository root.
set -euo pipefail
cd "$(dirname "$0")/.."
[ $# -gt 0 ] || set -- .
for m in "$@"; do
	(
		cd "$m"
		go vet -tags linkdebug ./...
		# shellcheck disable=SC2016
		list=$(go list -f '{{.ImportPath}} {{.Dir}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... |
			awk '{ for (i = 3; i <= NF; i++) if ($i ~ /^github\.com\/nfltr\/link(\/|$)/) { print $1, $2; break } }')
		[ -n "$list" ] || exit 0
		pkgs=""
		while read -r pkg pdir; do
			if ! grep -qs 'leakcheck\.Run' "$pdir"/*_test.go; then
				echo "test-linkdebug: $pkg imports link but its TestMain is not leakcheck's: its link debug reports would go unseen" >&2
				exit 1
			fi
			pkgs="$pkgs $pkg"
		done <<<"$list"
		# leakcheck's own test: a report is counted
		pkgs="$pkgs ./internal/leakcheck"
		# shellcheck disable=SC2086
		go test -count=1 -tags linkdebug $pkgs
	)
done
