#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# ci.sh: `make ci`, the commands this repository's GitHub workflow runs on a
# push, run here in the same order. GitHub Actions is not a gate for nfltr
# repositories; this is (before a push: the pre-push hook, scripts/pre-push;
# after it: the Linux runner, nfltr's deploy/linux-node/ci-runner.sh).
#
#   scripts/ci.sh [run]           run the steps; a pass is stamped against the tree
#   scripts/ci.sh steps           print the steps, one per line: <dir><TAB><command>
#   scripts/ci.sh verified [rev]  exit 0 when rev's (default HEAD) tree has a pass stamp
#   scripts/ci.sh self-test       the workflow parser against a sample workflow
#
# The steps are read from the workflow file (CI_WORKFLOW, default the only
# file in .github/workflows), so `make ci` and the workflow cannot drift:
#   - every job, except one whose `if:` limits it to other events
#     (github.event_name == ...: schedule- or dispatch-only jobs);
#   - its `run:` steps in order, a `${{ matrix.<key> }}` step once per value
#     of the job's one-line matrix list, in the job's
#     defaults.run.working-directory, with its job-level `env:`;
#   - a step that uses GitHub's token (GITHUB_TOKEN) is GitHub's own setup
#     and is skipped: here git uses this machine's credentials;
#   - anything else it does not understand (a multi-line run, another
#     ${{ }} expression, a step-level if/env/working-directory, a top-level
#     env or defaults) fails closed.
# Each step runs as GitHub runs it: bash -eo pipefail, stopping at the first
# failure (`ci: FAIL step i/n: <command>`, the line the runner reports).
#
# Stamps: a pass on a clean tree is recorded under
# <git-common-dir>/ci-verified/ against the tree and the Go toolchain; a
# later `make ci` or push of the identical tree skips the run (CI_FORCE=1
# runs it anyway). Stamps older than 30 days are pruned.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
WF="${CI_WORKFLOW:-$(ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null | head -n 1)}"

# parse <workflow>: the steps as <dir>\t<command>; exit 1 with a reason on
# anything outside the supported subset.
parse() {
	awk '
	function die(m) { printf "ci.sh: %s:%d: %s\n", FILENAME, NR, m > "/dev/stderr"; bad = 1; exit 1 }
	function ind(s) { match(s, /^ */); return RLENGTH }
	function val(s) { sub(/^[^:]*:[ ]*/, "", s); sub(/[ ]+#.*$/, "", s); gsub(/^["\047]|["\047]$/, "", s); return s }
	function endstep() {
		if (!instep) return
		instep = 0
		if (srun == "") return
		if (srun ~ /GITHUB_TOKEN/ || senv ~ /github\.token/) return
		if (srun ~ /^[|>]/) die("multi-line run: is not supported")
		if (sother != "") die("step-level " sother " is not supported")
		steps[++ns] = srun
	}
	function endjob(   i, c, k, v, n, vals) {
		endstep()
		if (job != "" && !skip) {
			for (i = 1; i <= ns; i++) {
				c = steps[i]
				if (c ~ /\$\{\{ *matrix\./) {
					if (mkey == "") die("job " job ": matrix expression without a one-line matrix list")
					n = split(mvals, vals, /,[ ]*/)
					for (v = 1; v <= n; v++) { k = c; gsub("\\$\\{\\{ *matrix\\." mkey " *\\}\\}", vals[v], k); emit(k) }
				} else emit(c)
			}
		}
		job = ""; skip = 0; ns = 0; jenv = ""; jdir = "."; mkey = ""; mvals = ""; inenv = 0; inmatrix = 0; indefaults = 0
	}
	function emit(c) {
		if (c ~ /\$\{\{/) die("job " job ": unsupported expression in: " c)
		printf "%s\t%s%s\n", jdir, jenv, c
		emitted++
	}
	/^[ ]*#/ || /^[ ]*$/ { next }
	ind($0) == 0 {
		endjob(); injobs = ($0 ~ /^jobs:/)
		if ($0 ~ /^(env|defaults):/) die("top-level " $1 " is not supported")
		next
	}
	!injobs { next }
	ind($0) == 2 { endjob(); job = $1; sub(/:$/, "", job); next }
	ind($0) == 4 {
		endstep(); inenv = ($0 ~ /^    env:/); inmatrix = 0; indefaults = ($0 ~ /^    defaults:/)
		if ($0 ~ /^    if:/ && $0 ~ /github\.event_name ==/) skip = 1
		next
	}
	inenv && ind($0) == 6 { k = $1; sub(/:$/, "", k); jenv = jenv "export " k "=\047" val($0) "\047; "; next }
	indefaults && $0 ~ /working-directory:/ { jdir = val($0); next }
	$0 ~ /^ +matrix:[ ]*$/ { inmatrix = 1; next }
	inmatrix && $0 ~ /^ +[A-Za-z_-]+:[ ]*\[.*\][ ]*$/ {
		if (mkey != "") die("job " job ": only one matrix key is supported")
		mkey = $1; sub(/:$/, "", mkey); mvals = val($0); gsub(/^\[|\]$/, "", mvals); next
	}
	$0 ~ /^ +- / && ind($0) == 6 { endstep(); instep = 1; srun = ""; senv = ""; sother = ""; sub(/- /, "  ") }
	instep && ind($0) == 8 {
		if ($0 ~ /^ +run:/) srun = val($0)
		else if ($0 ~ /^ +env:/) senv = "env"
		else if ($0 ~ /^ +(if|working-directory|shell):/) { k = $1; sub(/:$/, "", k); sother = k }
		next
	}
	instep && ind($0) > 8 && senv != "" { senv = senv " " $0; next }
	END { if (bad) exit 1; endjob(); if (bad) exit 1; if (!emitted) { print "ci.sh: " FILENAME ": no steps found" > "/dev/stderr"; exit 1 } }
	' "$1"
}

stamp_key() { # stamp_key <rev>
	{ git rev-parse "$1^{tree}" && go version; } | shasum -a 256 | cut -c1-40
}
STAMPS="$(git rev-parse --git-common-dir 2>/dev/null)/ci-verified"

self_test() {
	local d want got
	d="$(mktemp -d)" || return 1
	cat >"$d/wf.yml" <<'EOF'
name: sample
on: {push: {branches: [main]}}
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      GOPRIVATE: github.com/x/*
    steps:
      - uses: actions/checkout@v4
      - run: git config --global url."https://x:${GITHUB_TOKEN}@github.com/x".insteadOf https://github.com/x
        env:
          GITHUB_TOKEN: ${{ github.token }}
      - run: make build # comment
      - name: tests
        run: make test
  b:
    if: github.event_name != 'schedule'
    strategy:
      matrix:
        target: [t1, t2]
    steps:
      - run: make ${{ matrix.target }}
  nightly:
    if: github.event_name == 'schedule'
    steps:
      - run: make soak
  web:
    defaults:
      run:
        working-directory: web
    steps:
      - run: npm test
EOF
	want="$(printf '.\texport GOPRIVATE=%sgithub.com/x/*%s; make build\n.\texport GOPRIVATE=%sgithub.com/x/*%s; make test\n.\tmake t1\n.\tmake t2\nweb\tnpm test' "'" "'" "'" "'")"
	got="$(parse "$d/wf.yml")" || { rm -rf "$d"; echo "ci.sh self-test: parse failed" >&2; return 1; }
	if [ "$got" != "$want" ]; then
		printf 'ci.sh self-test: got\n%s\nwant\n%s\n' "$got" "$want" >&2
		rm -rf "$d"
		return 1
	fi
	printf 'jobs:\n  a:\n    steps:\n      - run: |\n          make x\n' >"$d/bad.yml"
	if parse "$d/bad.yml" >/dev/null 2>&1; then echo "ci.sh self-test: a multi-line run was accepted" >&2; rm -rf "$d"; return 1; fi
	printf 'jobs:\n  a:\n    steps:\n      - if: failure()\n        run: make x\n' >"$d/bad.yml"
	if parse "$d/bad.yml" >/dev/null 2>&1; then echo "ci.sh self-test: a step-level if was accepted" >&2; rm -rf "$d"; return 1; fi
	rm -rf "$d"
}

run() {
	local steps n i dir cmd key="" started=$SECONDS t
	self_test || exit 1
	[ -n "$WF" ] && [ -f "$WF" ] || { echo "ci.sh: no workflow file (CI_WORKFLOW)" >&2; exit 1; }
	steps="$(parse "$WF")" || exit 1
	if [ -z "$(git status --porcelain 2>/dev/null)" ] && git rev-parse -q --verify HEAD >/dev/null; then
		key="$(stamp_key HEAD)"
		if [ -z "${CI_FORCE:-}" ] && [ -f "$STAMPS/$key" ]; then
			echo "ci: ok, verified for this exact tree ($(git rev-parse --short HEAD), $(go version | cut -d' ' -f3)); CI_FORCE=1 runs it again"
			exit 0
		fi
	fi
	n="$(printf '%s\n' "$steps" | wc -l | tr -d ' ')"
	i=0
	while IFS="$(printf '\t')" read -r dir cmd; do
		i=$((i + 1))
		t=$SECONDS
		echo "ci: [$i/$n] ${dir}: $cmd"
		if ! (cd "$dir" && CI=true bash --noprofile --norc -eo pipefail -c "$cmd") </dev/null; then
			echo "ci: FAIL step $i/$n: $cmd (after $((SECONDS - started))s)"
			exit 1
		fi
		echo "ci: [$i/$n] ok in $((SECONDS - t))s"
	done <<EOF
$steps
EOF
	if [ -n "$key" ]; then
		mkdir -p "$STAMPS" && : >"$STAMPS/$key"
		find "$STAMPS" -type f -mtime +30 -delete 2>/dev/null || true
	fi
	echo "ci: ok, $n steps in $((SECONDS - started))s"
}

case "${1:-run}" in
run) run ;;
steps) parse "$WF" ;;
verified) [ -f "$STAMPS/$(stamp_key "${2:-HEAD}")" ] ;;
self-test) self_test && echo "ci.sh self-test: ok" ;;
*) echo "usage: scripts/ci.sh [run|steps|verified [rev]|self-test]" >&2; exit 2 ;;
esac
