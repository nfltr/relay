#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# check-dep-ports.sh: every external dependency is reached through a port this
# repository owns; only its adapter and the escape hatches (migration, backup
# and restore, break-glass tools) import or name it (nfltr
# docs/decisions/dependencies-behind-ports-2026-11-27.md). Identical in nfltr,
# hosted, link, relay, relay-core, relay-server, send and pipe (nfltr's copy is
# the source; change it there, then copy it unchanged).
#
#   check-dep-ports.sh            the tree against scripts/dep-ports.txt and
#                                 scripts/dep-ports-allow.txt
#   check-dep-ports.sh --update   rewrite the allow-list to today's violations
#                                 (review the diff: it may only shrink)
#   check-dep-ports.sh self-test  the checker's rules on a scratch repository
#
# scripts/dep-ports.txt, one rule per line: NAME KIND PATTERN ALLOWED...
#   KIND import  PATTERN is an ERE for an import path's start, matched on the
#                import lines of tracked .go files
#   KIND name    PATTERN is an ERE matched in tracked text files except docs
#                (*.md, docs/, web/docs/), this checker and its two files
#   ALLOWED      git pathspec globs: the adapter and the escape hatches
# scripts/dep-ports-allow.txt, "NAME FILE" per violation that exists today. It
# may only shrink: a new violation fails, a fixed one's entry is stale and
# fails, and (when DEP_PORTS_BASE, default origin/main, resolves) an entry the
# base did not list for a rule the base had fails too.
# Exit: 0 clean, 1 a violation or a stale entry, 2 usage.
set -euo pipefail
set -f # ALLOWED globs are git pathspecs, never shell globs
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
RULES=scripts/dep-ports.txt
ALLOW=scripts/dep-ports-allow.txt

rules() { sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "${1:-$RULES}"; }
entries() { sed -e 's/#.*//' -e '/^[[:space:]]*$/d' -e 's/[[:space:]][[:space:]]*/ /g' -e 's/ $//' "$1" | sort -u; }

# violations: "NAME FILE" for each tracked file that imports or names a
# dependency outside its rule's ALLOWED paths; a rule whose ALLOWED glob
# matches no file is reported on stderr and fails (a stale rule).
violations() {
	local name kind pat allowed a re bad=0
	local -a ex
	while read -r name kind pat allowed; do
		ex=(":(exclude)vendor" ":(exclude,glob)**/vendor/**" ":(exclude)$RULES" ":(exclude)$ALLOW" ":(exclude)scripts/check-dep-ports.sh")
		for a in $allowed; do
			if [ -z "$(git ls-files -- ":(glob)$a" | sed -n 1p)" ]; then
				echo "dep-ports: rule $name allows $a, which matches no tracked file" >&2
				bad=1
			fi
			ex+=(":(exclude,glob)$a")
		done
		case $kind in
		import)
			re='^[[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_]*[[:space:]]+)?"('"$pat"')'
			git grep -l -E "$re" -- '*.go' "${ex[@]}" | sed "s|^|$name |" || true ;;
		name)
			git grep -l -I -E "$pat" -- . ':(exclude,glob)**/*.md' ':(exclude)docs' ':(exclude)web/docs' "${ex[@]}" | sed "s|^|$name |" || true ;;
		*) echo "dep-ports: rule $name: unknown kind $kind" >&2; bad=1 ;;
		esac
	done < <(rules)
	return $bad
}

check() {
	local root new stale grown rc=0 got="$T/got" allow="$T/allow" base="$T/base"
	root="$(git rev-parse --show-toplevel)" && cd "$root"
	[ -f "$RULES" ] || { echo "dep-ports: no $RULES" >&2; exit 2; }
	violations | sort -u >"$got" || rc=1
	if [ "${1:-}" = --update ]; then
		{ echo "# NAME FILE: violations of scripts/dep-ports.txt that exist today (check-dep-ports.sh --update); it may only shrink."; cat "$got"; } >"$ALLOW"
		echo "dep-ports: wrote $ALLOW ($(wc -l <"$got" | tr -d ' ') entries)"
		return $rc
	fi
	[ -f "$ALLOW" ] && entries "$ALLOW" >"$allow" || : >"$allow"
	new="$(comm -23 "$got" "$allow")"
	stale="$(comm -13 "$got" "$allow")"
	if [ -n "$new" ]; then
		echo "dep-ports: these files reach a dependency outside its adapter (scripts/dep-ports.txt); use the port, or add an escape-hatch path to the rule:" >&2
		echo "$new" | sed 's/^/  /' >&2
		rc=1
	fi
	if [ -n "$stale" ]; then
		echo "dep-ports: stale $ALLOW entries (fixed; delete them):" >&2
		echo "$stale" | sed 's/^/  /' >&2
		rc=1
	fi
	local ref="${DEP_PORTS_BASE:-origin/main}"
	if git rev-parse -q --verify "$ref^{commit}" >/dev/null &&
		git show "$ref:$RULES" >"$base.rules" 2>/dev/null; then
		git show "$ref:$ALLOW" 2>/dev/null >"$base" || : >"$base"
		entries "$base" >"$base.sorted" && mv "$base.sorted" "$base"
		grown="$(comm -23 "$allow" "$base" | while read -r name file; do
			rules "$base.rules" | awk -v n="$name" '$1 == n { f = 1 } END { exit !f }' && echo "$name $file"
		done)"
		if [ -n "$grown" ]; then
			echo "dep-ports: $ALLOW grew against $ref (it may only shrink; fix these through the port):" >&2
			echo "$grown" | sed 's/^/  /' >&2
			rc=1
		fi
	fi
	[ $rc -ne 0 ] || echo "dep-ports: ok ($(rules | wc -l | tr -d ' ') rules, $(wc -l <"$allow" | tr -d ' ') allow-listed)"
	return $rc
}

selftest() {
	local d="$T/repo" v
	for v in $(compgen -e); do case $v in GIT_*) unset "$v" ;; esac; done
	mkdir "$d"
	(
		cd "$d" && git init -q -b main && git config user.email t@t && git config user.name t
		mkdir -p scripts store app
		printf 'sql import github\\.com/jackc/pgx store/**\ncf name api\\.cloudflare\\.com store/cf.sh\n' >"$RULES"
		printf 'package store\n\nimport (\n\t"fmt"\n\tpgx "github.com/jackc/pgx/v5"\n)\n' >store/s.go
		echo 'curl https://api.cloudflare.com/x' >store/cf.sh
		printf 'package app\n\nimport "github.com/jackc/pgx/v5/pgconn"\n' >app/a.go
		echo 'notes on api.cloudflare.com' >app/README.md
		cp "$SELF" scripts/check-dep-ports.sh # its fixtures name what it checks
		git add -A && git commit -qm base
		! bash "$SELF" 2>/dev/null || { echo "self-test: a new violation passed" >&2; exit 1; }
		bash "$SELF" --update >/dev/null
		[ "$(entries "$ALLOW")" = "sql app/a.go" ] || { echo "self-test: allow-list is $(entries "$ALLOW")" >&2; exit 1; }
		bash "$SELF" >/dev/null || { echo "self-test: an allow-listed violation failed" >&2; exit 1; }
		git add -A && git commit -qm allow && git update-ref refs/remotes/origin/main HEAD
		echo 'curl api.cloudflare.com' >app/b.sh && git add -A
		! bash "$SELF" 2>/dev/null || { echo "self-test: a new name violation passed" >&2; exit 1; }
		echo 'cf app/b.sh' >>"$ALLOW"
		! bash "$SELF" 2>/dev/null || { echo "self-test: an allow-list that grew passed" >&2; exit 1; }
		git rm -q --cached app/b.sh && rm app/b.sh && sed -i.bak '/app\/b.sh/d' "$ALLOW" && rm -f "$ALLOW.bak"
		git rm -q app/a.go
		! bash "$SELF" 2>/dev/null || { echo "self-test: a stale entry passed" >&2; exit 1; }
		: >"$ALLOW"
		bash "$SELF" >/dev/null || { echo "self-test: a clean tree failed" >&2; exit 1; }
		echo 'x import foo nowhere/**' >>"$RULES"
		! bash "$SELF" 2>/dev/null || { echo "self-test: a rule allowing no file passed" >&2; exit 1; }
	) || return 1
	echo "dep-ports: self-test ok"
}

case "${1:-}" in
'' | --update) check "${1:-}" ;;
self-test) selftest ;;
*) echo "usage: check-dep-ports.sh [--update | self-test]" >&2; exit 2 ;;
esac
