#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# check-grepq.sh: no early-exit consumer at the end of a pipe in a script
# that runs under pipefail. Identical in nfltr, hosted, link, relay,
# relay-core and relay-server (nfltr's copy is the source; change it there,
# then copy it unchanged).
#
# Under `set -o pipefail`, `producer | grep -q X` reads "not found" when grep
# exits on its first match and the producer's next write dies of SIGPIPE
# (exit 141): a race with the producer's write pattern and the machine's load
# (lane BOXDASH: hosted's monitoring.sh deleted a wanted uptime check 47 times
# in 48,000 under load). `| grep -m N` and `| head` exit early the same way.
# Read all of the input instead:
#   producer | grep -q X        ->  producer | grep X >/dev/null
#   x=$(producer | head -n 1)   ->  x=$(producer | sed -n 1p)
#   producer | head -c N        ->  producer | { head -c N; cat >/dev/null; }
# (a follow-mode producer, `tail -f` or `logs -f`, never ends: there the early
# exit is the point, so keep it and allow-list the line).
#
#   check-grepq.sh              every tracked shell script of this repository
#                               (`*.sh`, `*.bash` or a sh/bash shebang; not
#                               vendor/, node_modules/ or this file, whose
#                               self-test races on purpose) that sets pipefail,
#                               plus every `*.sh` without a shebang (a sourced
#                               library runs under its caller's options).
#                               Allow-list: scripts/grepq-allow.txt, lines
#                               `<path>:<line> -- <reason>`; a stale entry (no
#                               finding at that line) fails too.
#   check-grepq.sh FILE...      those files, no allow-list.
#   check-grepq.sh self-test    the race reproduced and the scanner's rules.
# Exit: 0 clean, 1 a finding or a stale entry, 2 usage.
set -eu

# scan FILE...: "<file>:<line>: <text>" for each finding.
scan() {
	awk -v sq="'" '
	# consumer(str): the command a pipe feeds, its unquoted words only (a
	# quoted word becomes Q), up to the next |, ;, & or unmatched ).
	function consumer(str,   i, n, ch, nx, sp, st, top, bare) {
		sp = 0; bare = ""; n = length(str)
		for (i = 1; i <= n; i++) {
			ch = substr(str, i, 1); nx = substr(str, i + 1, 1)
			top = sp ? st[sp] : "c"
			if (top == "s") { if (ch == sq) sp--; continue }
			if (ch == "\\") { if (!sp) bare = bare ch nx; i++; continue }
			if (top == "d") {
				if (ch == "\"") sp--
				else if (ch == "$" && nx == "(") { st[++sp] = "c"; i++ }
				continue
			}
			if (ch == sq || ch == "\"") { if (!sp) bare = bare " Q "; st[++sp] = (ch == sq ? "s" : "d"); continue }
			if (ch == "(") { st[++sp] = "c"; continue }
			if (ch == ")") { if (!sp) break; sp--; continue }
			if (!sp && (ch == "|" || ch == ";" || ch == "&" || ch == "#")) break
			if (!sp) bare = bare ch
		}
		return bare
	}
	function early(cmd) {
		sub(/^[ \t]+/, "", cmd)
		if (cmd ~ /^(command[ \t]+)?[ef]?grep([ \t]|$)/ && (cmd ~ /[ \t]-[A-Za-z]*[qm]/ || cmd ~ /[ \t]--(quiet|silent|max-count)/)) return 1
		return cmd ~ /^head([ \t]|$)/
	}
	# pipes(str): 1 when an unquoted pipe in str feeds an early-exit
	# consumer; tail is set when str ends in an unquoted pipe.
	function pipes(str,   i, n, ch, nx, pr, sp, st, top, hit) {
		sp = 0; hit = 0; tail = 0; n = length(str); pr = " "
		for (i = 1; i <= n; i++) {
			ch = substr(str, i, 1); nx = substr(str, i + 1, 1)
			top = sp ? st[sp] : "c"
			if (top == "s") { if (ch == sq) sp--; pr = ch; continue }
			if (ch == "\\") { i++; pr = nx; continue }
			if (top == "d") {
				if (ch == "\"") sp--
				else if (ch == "$" && nx == "(") { st[++sp] = "c"; i++ }
				pr = ch; continue
			}
			if (ch == sq) st[++sp] = "s"
			else if (ch == "\"") st[++sp] = "d"
			else if (ch == "(") st[++sp] = "c"
			else if (ch == ")") { if (sp) sp-- }
			else if (ch == "#" && pr ~ /[ \t;]/) break
			else if (ch == "|") {
				if (nx == "|") { i++; pr = nx; continue }
				rest = substr(str, i + (nx == "&" ? 2 : 1))
				if (rest ~ /^[ \t]*(\\)?$/) tail = 1
				else if (early(consumer(rest))) hit = 1
			}
			pr = ch
		}
		return hit
	}
	FNR == 1 {
		if (prevfile != "") flush()
		prevfile = FILENAME; n = 0; ptail = 0
		pf = (FILENAME ~ /\.sh$/ && $0 !~ /^#!/)
	}
	{
		code = $0; sub(/^[ \t]+/, "", code)
		if (code ~ /^#/ || code == "") next
		if (code ~ /^(set|shopt|bash|sh)[ \t]/ && code ~ /pipefail/) pf = 1
		hit = pipes($0)
		if (ptail && early(consumer($0))) hit = 1
		ptail = tail
		if (hit) { n++; L[n] = FNR; T[n] = $0 }
	}
	function flush(   k) {
		if (pf) for (k = 1; k <= n; k++) print prevfile ":" L[k] ": " T[k]
	}
	END { if (prevfile != "") flush() }
	' "$@"
}

# repo_files: the tracked shell scripts of the repository.
repo_files() {
	git ls-files | while IFS= read -r f; do
		case "$f" in vendor/* | */vendor/* | node_modules/* | */node_modules/* | scripts/check-grepq.sh) continue ;; esac
		[ -f "$f" ] || continue
		case "$f" in
		*.sh | *.bash) printf '%s\n' "$f" ;;
		*.*) ;;
		*) head -n 1 "$f" 2>/dev/null | grep -E '^#!.*[/ ](ba)?sh([ \t]|$)' >/dev/null && printf '%s\n' "$f" ;;
		esac
	done
}

check_repo() {
	cd "$(git rev-parse --show-toplevel)"
	allow=scripts/grepq-allow.txt
	found=$(repo_files | while IFS= read -r f; do scan "$f"; done)
	rc=0
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		key=${f%%: *}
		if [ -f "$allow" ] && grep -F -x -e "$key" <(sed -n 's/^\([^ #][^ ]*:[0-9][0-9]*\) -- ..*/\1/p' "$allow") >/dev/null; then continue; fi
		echo "check-grepq: $f" >&2
		rc=1
	done <<<"$found"
	if [ -f "$allow" ]; then
		while IFS= read -r key; do
			[ -n "$key" ] || continue
			printf '%s\n' "$found" | grep -F -e "$key: " >/dev/null || { echo "check-grepq: stale allow-list entry $key (no early-exit pipe there)" >&2; rc=1; }
		done < <(sed -n 's/^\([^ #][^ ]*:[0-9][0-9]*\) -- ..*/\1/p' "$allow")
	fi
	if [ "$rc" != 0 ]; then
		echo "check-grepq: a pipe ending in grep -q/-m or head under pipefail reads SIGPIPE (141) as failure; read all the input (see the header of scripts/check-grepq.sh) or allow-list <path>:<line> -- <reason> in $allow" >&2
	fi
	return "$rc"
}

self_test() {
	t=$(mktemp -d "${TMPDIR:-/tmp}/check-grepq.XXXXXX")
	trap 'rm -rf "$t"' EXIT
	fail() { echo "check-grepq self-test: FAIL: $*" >&2; exit 1; }

	# 1. The race. A producer whose second write lands after grep -q (or
	# head) has exited dies of SIGPIPE; under pipefail the pipeline fails
	# although the match was there. The sleep stands in for load between two
	# writes; the read-all forms pass.
	set -o pipefail
	rc=0; { echo up; sleep 0.2; echo more; } | grep -q up || rc=$?
	[ "$rc" = 141 ] || fail "producer | grep -q under pipefail: want 141 (SIGPIPE), got $rc"
	rc=0; { echo up; sleep 0.2; echo more; } | head -n 1 >/dev/null || rc=$?
	[ "$rc" = 141 ] || fail "producer | head under pipefail: want 141, got $rc"
	{ echo up; sleep 0.2; echo more; } | grep up >/dev/null || fail "producer | grep >/dev/null: want 0"
	[ "$({ echo up; sleep 0.2; echo more; } | sed -n 1p)" = up ] || fail "producer | sed -n 1p"
	# The same race without the sleep, many times (load decides how often it
	# fires; reported, not asserted).
	lost=0; i=0
	while [ "$i" -lt "${GREPQ_LOOP:-300}" ]; do
		printf '%s\n' up a b c d e f g h | grep -q up || lost=$((lost + 1))
		i=$((i + 1))
	done
	set +o pipefail
	echo "check-grepq self-test: printf | grep -q under pipefail lost $lost of ${GREPQ_LOOP:-300} matches here"

	# 2. The scanner flags each early-exit consumer in a pipefail script...
	cat >"$t/bad.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$x" | grep -q up && echo yes
if docker ps | grep -qE '^relay'; then :; fi
x=$(ls | head -n 1)
y=$(git log 2>&1 | head -1)
z=$(ps | grep -m1 relay)
w=$(ps | command grep --quiet relay)
v=$(ps |
	grep -Fq relay)
ps | grep -E 'a|b' -q
EOF
	got=$(scan "$t/bad.sh" | sed 's/: .*//; s/.*://' | tr '\n' ' ')
	[ "$got" = "3 4 5 6 7 8 10 11 " ] || fail "bad.sh findings at lines '$got', want '3 4 5 6 7 8 10 11 '"
	# ...and not the read-all forms, an `||`, a comment, or a file without
	# pipefail (a shebang script that does not set it).
	cat >"$t/good.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$x" | grep up >/dev/null && echo yes
grep -q up <<<"$x"
[ -f a ] || grep -q up a
x=$(ls | sed -n 1p)
y=$(ps | { head -c 10; cat >/dev/null; })
# ps | grep -q relay
n=$(ps | grep -c relay)
l=$(ps | grep -n "nfltr -m cp" | cut -d: -f1)
echo 'ps | grep -q relay' "a | head"
EOF
	cat >"$t/nopf.sh" <<'EOF'
#!/bin/sh
set -eu
ps | grep -q relay
EOF
	got=$(scan "$t/good.sh" "$t/nopf.sh")
	[ -z "$got" ] || fail "false findings: $got"
	# A sourced library (no shebang) runs under its caller's pipefail.
	printf 'f() { ps | grep -q relay; }\n' >"$t/lib.sh"
	[ -n "$(scan "$t/lib.sh")" ] || fail "a sourced *.sh without a shebang is not scanned"

	# 3. The repository mode: an allow-listed finding passes, a stale entry
	# and an unlisted finding fail.
	r="$t/repo"
	mkdir -p "$r/scripts"
	cp "$t/bad.sh" "$r/scripts/a.sh"
	git -C "$r" init -q
	git -C "$r" add scripts/a.sh
	(cd "$r" && check_repo) 2>/dev/null && fail "repository mode passed with findings"
	: >"$r/scripts/grepq-allow.txt"
	for l in 3 4 5 6 7 8 10 11; do echo "scripts/a.sh:$l -- self-test" >>"$r/scripts/grepq-allow.txt"; done
	(cd "$r" && check_repo) || fail "repository mode failed with every finding allow-listed"
	echo "scripts/a.sh:2 -- stale" >>"$r/scripts/grepq-allow.txt"
	(cd "$r" && check_repo) 2>/dev/null && fail "repository mode passed a stale allow-list entry"
	echo "check-grepq self-test: ok"
}

case "${1:-}" in
"") check_repo ;;
self-test) self_test ;;
-*) echo "usage: check-grepq.sh [self-test | FILE...]" >&2; exit 2 ;;
*) out=$(scan "$@"); [ -z "$out" ] || { printf '%s\n' "$out"; exit 1; } ;;
esac
