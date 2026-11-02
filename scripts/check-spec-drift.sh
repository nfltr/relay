#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# check-spec-drift.sh: code that a TLA+ spec models does not change without
# its spec. Identical in nfltr, link, relay, relay-core and relay-server
# (nfltr's copy is the source; its test is scripts/check_spec_drift_test.sh;
# change it there, then copy it unchanged).
#
#   check-spec-drift.sh RANGE   every commit range A..B: for each spec
#                               directory (a README.md under spec/) whose
#                               code map names a file the range changes, the
#                               range must also change that directory, or a
#                               commit in it must carry the trailer
#                               `Spec-Reviewed: <spec> <reason>` (<spec>: the
#                               directory, its base name or a .tla module in
#                               it; the reason says why the spec still holds).
#   check-spec-drift.sh ci      RANGE origin/main..HEAD, fetching origin/main
#                               (and deepening a shallow clone) when needed;
#                               passes with a note when no common history is
#                               found (the pre-push hook gates main).
#   check-spec-drift.sh maps [REV]  every code-map entry names a path that
#                               exists at REV (default HEAD).
#
# Code map: the table rows under a README heading containing "Code map"
# (any level, up to the next heading). The last column lists the files:
# repo-relative paths, each containing a "/" (`a/b.go`, `a/b.go:10-40`,
# a directory `a/b/`, or a glob `a/*_trace.go`), optionally in backticks;
# other words are ignored. A legend line "`X/` = `long/path/`" anywhere in
# the README expands the prefix X/.
# Exit: 0 clean, 1 drift or a stale map entry, 2 usage.
set -eu
cd "$(git rev-parse --show-toplevel)"

# maps_of REV: lines "<spec dir>\t<path entry>" for every code map at REV.
maps_of() {
	git ls-tree -r --name-only "$1" -- spec | grep '/README\.md$' | while read -r f; do
		git show "$1:$f" | awk -v d="${f%/README.md}" '
			{ lines[NR] = $0; r = $0
				while (match(r, /`[A-Za-z0-9_]+\/` = `[^`]+\/`/)) {
					s = substr(r, RSTART + 1, RLENGTH - 2); r = substr(r, RSTART + RLENGTH)
					split(s, kv, /` = `/); legend[kv[1]] = kv[2] } }
			END {
				for (i = 1; i <= NR; i++) {
					l = lines[i]
					if (l ~ /^#/) { inmap = (tolower(l) ~ /code map/); continue }
					if (!inmap || l !~ /^\|/ || l ~ /^\|[ :|-]+\|?[ \t]*$/) continue
					n = split(l, col, "|"); c = col[n]; if (c ~ /^[ \t]*$/) c = col[n - 1]
					m = split(c, w, /[ ,;]+/)
					for (j = 1; j <= m; j++) {
						t = w[j]; gsub(/`/, "", t); sub(/:[0-9][0-9,-]*$/, "", t)
						if (t !~ /\// || t !~ /^[A-Za-z0-9_.*\/-]+$/ || t ~ /^\//) continue
						for (k in legend) if (index(t, k) == 1) { t = legend[k] substr(t, length(k) + 1); break }
						print d "\t" t
					}
				}
			}'
	done
}

# covers ENTRY FILE: ENTRY (path, dir/ or glob) names FILE.
covers() {
	case "$1" in
	*/) case "$2" in "$1"*) return 0 ;; esac ;;
	*) case "$2" in $1) return 0 ;; esac ;;
	esac
	return 1
}

check_maps() {
	rev=${1:-HEAD}
	t=$(mktemp -d)
	git ls-tree -r --name-only "$rev" >"$t/files"
	maps_of "$rev" >"$t/maps"
	[ -s "$t/maps" ] || echo "spec drift: no code map in any spec/**/README.md at $rev"
	st=0
	awk -F'\t' -v rev="$rev" '
		NR == FNR { have[$0] = 1; files[++n] = $0; next }
		{ e = $2; hit = (e in have)
		  if (!hit && (e ~ /\/$/ || e ~ /\*/)) {
			re = e; gsub(/\./, "\\.", re); gsub(/\*/, "[^/]*", re)
			re = "^" re (e ~ /\/$/ ? "" : "$")
			for (i = 1; i <= n && !hit; i++) if (files[i] ~ re) hit = 1
		  }
		  if (!hit) { print "spec drift: " $1 "/README.md code map names " e ", which does not exist at " rev; bad = 1 } }
		END { exit bad }' "$t/files" "$t/maps" || st=$?
	rm -rf "$t"
	return $st
}

check_range() {
	range=$1 tip=${1#*..}
	t=$(mktemp -d)
	git log --no-merges --format= --name-only "$range" | sed '/^$/d' | sort -u >"$t/changed"
	git log --format=%B "$range" | sed -n 's/^Spec-Reviewed:[ 	]*\([^ 	]*\)[ 	]*\(.*\)$/\1	\2/p' >"$t/reviewed"
	maps_of "${tip:-HEAD}" >"$t/maps"
	bad=0
	for d in $(cut -f1 "$t/maps" | sort -u); do
		grep -q "^$d/" "$t/changed" && continue
		hits=$(grep "^$d	" "$t/maps" | cut -f2 | while read -r e; do
			while read -r f; do covers "$e" "$f" && echo "$f"; done <"$t/changed"
		done | sort -u)
		[ -n "$hits" ] || continue
		names=" $d $(basename "$d") $(git ls-tree --name-only "${tip:-HEAD}" -- "$d/" | sed -n 's|.*/\(.*\)\.tla$|\1|p' | tr '\n' ' ')"
		ok=0
		while IFS="	" read -r s why; do
			case "$names " in *" $s "*) [ -n "$why" ] && ok=1 ;; esac
		done <"$t/reviewed"
		[ $ok -eq 1 ] && { echo "spec drift: $d: reviewed (Spec-Reviewed trailer)"; continue; }
		echo "spec drift: $range changes code that $d models but not $d:"
		echo "$hits" | sed 's/^/  /'
		echo "  update the spec (or its README) in the same range, or add a commit trailer"
		echo "  'Spec-Reviewed: $d <why the spec still holds>'"
		bad=1
	done
	rm -rf "$t"
	return $bad
}

case "${1:-}" in
maps) check_maps "${2:-HEAD}" ;;
ci)
	git rev-parse -q --verify origin/main >/dev/null 2>&1 ||
		git fetch -q --depth=200 origin main:refs/remotes/origin/main 2>/dev/null || true
	[ "$(git rev-parse --is-shallow-repository)" = false ] || git fetch -q --deepen=200 origin 2>/dev/null || true
	if ! git merge-base origin/main HEAD >/dev/null 2>&1; then
		echo "spec drift: skipped, no common history with origin/main here (the pre-push hook checks main)"
		exit 0
	fi
	check_range "$(git merge-base origin/main HEAD)..HEAD"
	;;
*..*) check_range "$1" ;;
*)
	sed -n '4,32p' "$0" >&2
	exit 2
	;;
esac
