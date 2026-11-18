#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# ci.sh: `make ci`, the commands this repository's GitHub workflow runs on a
# push, run here in the same order. GitHub Actions is not a gate for nfltr
# repositories; the Linux runner (nfltr's deploy/linux-node/ci-runner.sh) runs
# this per sha and is the gate, which scripts/pre-push checks before a push.
#
#   scripts/ci.sh [run]           run the steps; a pass is stamped against the tree
#   scripts/ci.sh steps           print the steps, one per line: <job><TAB><dir><TAB><command>
#   scripts/ci.sh verified [rev]  exit 0 when rev's (default HEAD) tree has a pass stamp
#   scripts/ci.sh self-test       the workflow parser against a sample workflow and
#                                 the job runner's order, failure and concurrency
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
#     env or defaults, a job's needs:) fails closed.
# The jobs run at once, as on GitHub (at most CI_JOBS at a time, default the
# CPUs this process may use: the cgroup's cpu.max quota, else the online
# CPUs; CI_JOBS=1 runs them one after another), started in workflow order;
# a job's steps run in order, each as GitHub runs it: bash -eo pipefail.
# Jobs share this checkout, so a job must not change a file another job
# reads (GitHub gives each job a checkout of its own). Each job's output
# goes to a file of its own and is printed whole, in workflow order. The
# first failing step fails the run: `ci: FAIL step i/n: <command>` (the
# line the runner reports), the running jobs are stopped and named.
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
			if (needs) die("job " job ": needs: is not supported (make ci runs the jobs at once)")
			for (i = 1; i <= ns; i++) {
				c = steps[i]
				if (c ~ /\$\{\{ *matrix\./) {
					if (mkey == "") die("job " job ": matrix expression without a one-line matrix list")
					n = split(mvals, vals, /,[ ]*/)
					for (v = 1; v <= n; v++) { k = c; gsub("\\$\\{\\{ *matrix\\." mkey " *\\}\\}", vals[v], k); emit(k) }
				} else emit(c)
			}
		}
		job = ""; skip = 0; ns = 0; jenv = ""; jdir = "."; mkey = ""; mvals = ""; inenv = 0; inmatrix = 0; indefaults = 0; needs = 0
	}
	function emit(c) {
		if (c ~ /\$\{\{/) die("job " job ": unsupported expression in: " c)
		printf "%s\t%s\t%s%s\n", job, jdir, jenv, c
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
		if ($0 ~ /^    needs:/) needs = 1
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

TAB="$(printf '\t')"

# cpus: the CPUs this process may use: the cgroup's cpu.max quota (a
# container's --cpus), else the online CPUs.
cpus() {
	local q p
	if { read -r q p </sys/fs/cgroup/cpu.max; } 2>/dev/null && [ "$q" != max ] && [ "${p:-0}" -gt 0 ]; then
		echo $(((q + p - 1) / p))
		return
	fi
	getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
}

# descendants <pid>...: every process below them.
descendants() {
	ps -A -o pid= -o ppid= | awk -v roots="$*" '
		{ kids[$2] = kids[$2] " " $1 }
		END {
			n = split(roots, stack, " ")
			while (n > 0) {
				p = stack[n--]; m = split(kids[p], k, " ")
				for (j = 1; j <= m; j++) { print k[j]; stack[++n] = k[j] }
			}
		}'
}

# job <stepsfile> <n> <t0>: one job's steps (<i><TAB><dir><TAB><command>) in
# order, stopping at the first failure.
job() {
	local i dir cmd t
	while IFS="$TAB" read -r i dir cmd; do
		t=$(date +%s)
		echo "ci: [$i/$2] ${dir}: $cmd"
		if ! (cd "$dir" && CI=true bash --noprofile --norc -eo pipefail -c "$cmd") </dev/null; then
			echo "ci: FAIL step $i/$2: $cmd (after $(($(date +%s) - $3))s)"
			return 1
		fi
		echo "ci: [$i/$2] ok in $(($(date +%s) - t))s"
	done <"$1"
}

# execute <steps>: the parsed steps (<job><TAB><dir><TAB><command>), the jobs
# at once (at most CI_JOBS), each job's output printed whole in workflow
# order; exit 1 at the first failure, after stopping the running jobs.
execute() {
	local max="${CI_JOBS:-$(cpus)}" t0 tmp n=0 nj=0 next=1 shown=1 running=0 failed=0 k rc secs busy prev="" jb dir cmd
	local -a name st pid
	t0=$(date +%s)
	tmp="$(mktemp -d)" || return 1
	[ "$max" -ge 1 ] 2>/dev/null || max=1
	while IFS="$TAB" read -r jb dir cmd; do
		[ -n "$jb" ] || continue
		n=$((n + 1))
		if [ "$jb" != "$prev" ]; then
			nj=$((nj + 1)) && name[nj]=$jb && st[nj]="" && prev=$jb
		fi
		printf '%s\t%s\t%s\n' "$n" "$dir" "$cmd" >>"$tmp/$nj.steps"
	done <<EOF
$1
EOF
	echo "ci: $n steps in $nj jobs, at most $max at once"
	while [ "$shown" -le "$nj" ]; do
		while [ "$failed" = 0 ] && [ "$running" -lt "$max" ] && [ "$next" -le "$nj" ]; do
			(
				s=$(date +%s)
				job "$tmp/$next.steps" "$n" "$t0"
				rc=$?
				echo "$rc $(($(date +%s) - s))" >"$tmp/$next.rc.part" && mv "$tmp/$next.rc.part" "$tmp/$next.rc"
				exit $rc
			) >"$tmp/$next.log" 2>&1 &
			pid[next]=$!
			st[next]=running
			running=$((running + 1))
			next=$((next + 1))
		done
		busy=1
		k=$shown
		while [ "$k" -lt "$next" ]; do
			if [ "${st[k]}" = running ] && { [ -f "$tmp/$k.rc" ] || ! kill -0 "${pid[k]}" 2>/dev/null; }; then
				wait "${pid[k]}"
				rc=$?
				st[k]=$rc
				running=$((running - 1))
				busy=0
				[ "$rc" = 0 ] || [ "$failed" != 0 ] || failed=$k
			fi
			k=$((k + 1))
		done
		if [ "$failed" != 0 ]; then
			k=$shown
			prev=""
			while [ "$k" -lt "$next" ]; do
				[ "${st[k]}" != running ] || prev="$prev ${pid[k]}"
				k=$((k + 1))
			done
			# shellcheck disable=SC2046,SC2086
			[ -z "$prev" ] || kill -TERM $(descendants $prev) $prev 2>/dev/null
			wait
			k=$shown
			while [ "$k" -le "$nj" ]; do
				if [ "${st[k]}" = running ]; then
					echo "ci: job ${name[k]} stopped: job ${name[failed]} failed"
				elif [ -n "${st[k]}" ]; then
					cat "$tmp/$k.log"
				else
					echo "ci: job ${name[k]} not run: job ${name[failed]} failed"
				fi
				k=$((k + 1))
			done
			rm -rf "$tmp"
			return 1
		fi
		while [ "$shown" -le "$nj" ] && [ "${st[shown]}" = 0 ]; do
			cat "$tmp/$shown.log"
			read -r rc secs <"$tmp/$shown.rc"
			echo "ci: job ${name[shown]} ok in ${secs}s"
			shown=$((shown + 1))
		done
		[ "$busy" = 0 ] || sleep 0.2
	done
	rm -rf "$tmp"
	echo "ci: ok, $n steps in $(($(date +%s) - t0))s"
}

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
    needs: [a]
    steps:
      - run: make soak
  web:
    defaults:
      run:
        working-directory: web
    steps:
      - run: npm test
EOF
	want="$(printf 'a\t.\texport GOPRIVATE=%sgithub.com/x/*%s; make build\na\t.\texport GOPRIVATE=%sgithub.com/x/*%s; make test\nb\t.\tmake t1\nb\t.\tmake t2\nweb\tweb\tnpm test' "'" "'" "'" "'")"
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
	printf 'jobs:\n  a:\n    steps:\n      - run: make x\n  b:\n    needs: a\n    steps:\n      - run: make y\n' >"$d/bad.yml"
	if parse "$d/bad.yml" >/dev/null 2>&1; then echo "ci.sh self-test: a job's needs: was accepted" >&2; rm -rf "$d"; return 1; fi
	rm -rf "$d"
}

# exec_test: execute's order, concurrency, failure and stopping.
exec_test() {
	local d out t
	d="$(mktemp -d)" || return 1
	# Three one-second jobs at once take about a second, print in workflow
	# order whatever order they end in, and number the steps in workflow order.
	t=$(date +%s)
	out="$(CI_JOBS=3 execute "$(printf 'a\t.\tsleep 1; echo A1\na\t.\techo A2\nb\t.\tsleep 0.5; echo B1\nc\t.\techo C1; sleep 1\n')")" ||
		{ printf 'ci.sh exec-test: a passing run failed:\n%s\n' "$out" >&2; rm -rf "$d"; return 1; }
	[ $(($(date +%s) - t)) -le 2 ] || { echo "ci.sh exec-test: three 1 s jobs at once took $(($(date +%s) - t))s" >&2; rm -rf "$d"; return 1; }
	if [ "$(printf '%s\n' "$out" | grep -E '^(A|B|C)[0-9]$' | tr '\n' ' ')" != "A1 A2 B1 C1 " ] ||
		[ "$(printf '%s\n' "$out" | sed -n 's/^ci: \[\([0-9]\)\/4\] \.: .*/\1/p' | tr '\n' ' ')" != "1 2 3 4 " ]; then
		printf 'ci.sh exec-test: output out of order:\n%s\n' "$out" >&2
		rm -rf "$d"
		return 1
	fi
	# CI_JOBS=1 runs the jobs one after another.
	t=$(date +%s)
	CI_JOBS=1 execute "$(printf 'a\t.\tsleep 1\nb\t.\tsleep 1\n')" >/dev/null || { echo "ci.sh exec-test: a serial run failed" >&2; rm -rf "$d"; return 1; }
	[ $(($(date +%s) - t)) -ge 2 ] || { echo "ci.sh exec-test: CI_JOBS=1 ran jobs at once" >&2; rm -rf "$d"; return 1; }
	# A failing step fails the run at once, the job's later steps and the jobs
	# not started are not run, a running job is stopped (with its children),
	# and the failure is the line the runner reports.
	t=$(date +%s)
	if out="$(CI_JOBS=2 execute "$(printf 'a\t.\tsleep 2; touch %s/late\nb\t.\techo B1; exit 3\nb\t.\ttouch %s/after\nc\t.\ttouch %s/c\n' "$d" "$d" "$d")")"; then
		printf 'ci.sh exec-test: a failing run passed:\n%s\n' "$out" >&2
		rm -rf "$d"
		return 1
	fi
	[ $(($(date +%s) - t)) -le 1 ] || { echo "ci.sh exec-test: a failure waited for the other jobs" >&2; rm -rf "$d"; return 1; }
	printf '%s\n' "$out" | grep -qx 'ci: FAIL step 2/4: echo B1; exit 3 (after [0-9]*s)' &&
		printf '%s\n' "$out" | grep -qx 'B1' &&
		printf '%s\n' "$out" | grep -qx 'ci: job a stopped: job b failed' &&
		printf '%s\n' "$out" | grep -qx 'ci: job c not run: job b failed' ||
		{ printf 'ci.sh exec-test: failure output:\n%s\n' "$out" >&2; rm -rf "$d"; return 1; }
	sleep 2.5
	[ ! -e "$d/late" ] && [ ! -e "$d/after" ] && [ ! -e "$d/c" ] ||
		{ echo "ci.sh exec-test: a step ran after the failure: $(ls "$d")" >&2; rm -rf "$d"; return 1; }
	rm -rf "$d"
}

run() {
	local steps key=""
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
	execute "$steps" || exit 1
	# The jobs share this checkout: a step that changes it may race another
	# job, so name what changed (the stamp needs a clean tree anyway).
	[ -z "$key" ] || [ -z "$(git status --porcelain 2>/dev/null)" ] ||
		{ echo "ci: warning: the run changed the checkout:"; git status --porcelain | head -n 20; }
	if [ -n "$key" ]; then
		mkdir -p "$STAMPS" && : >"$STAMPS/$key"
		find "$STAMPS" -type f -mtime +30 -delete 2>/dev/null || true
	fi
}

case "${1:-run}" in
run) run ;;
steps) parse "$WF" ;;
verified) [ -f "$STAMPS/$(stamp_key "${2:-HEAD}")" ] ;;
self-test) self_test && exec_test && echo "ci.sh self-test: ok" ;;
*) echo "usage: scripts/ci.sh [run|steps|verified [rev]|self-test]" >&2; exit 2 ;;
esac
