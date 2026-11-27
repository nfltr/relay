# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# pool.sh, sourced by the spec scripts: checks side by side, SPEC_JOBS
# (default 4) at once, each TLC with one worker and TLC_JVMS set so the
# JVMs share the job's heap (scripts/fetch-tla.sh's java, CI_MEM_BUDGET_MB).
# A check takes a token from fd 9 to start and puts it back when it ends,
# so the next starts when any one ends. Outputs print in start order.
#   pool_start DIR  a pool whose outputs go to DIR (made, removed at the end)
#   pool CMD...     CMD in the background once a token is free; a nonzero
#                   exit fails the pool
#   pool_end        wait for every check, print each output, fail if any failed
pool_start() {
	pool_dir=$1 pool_n=0
	mkdir -p "$pool_dir"
	mkfifo "$pool_dir/tokens"
	exec 9<>"$pool_dir/tokens"
	pool_i=0
	while [ $pool_i -lt "${SPEC_JOBS:-4}" ]; do echo >&9; pool_i=$((pool_i + 1)); done
}

pool() {
	pool_n=$((pool_n + 1))
	read -r _ <&9
	(export TLC_JVMS="${SPEC_JOBS:-4}" TLC_WORKERS=1 && "$@" >"$pool_dir/$pool_n.out" 2>&1 || touch "$pool_dir/$pool_n.fail"; echo >&9) &
}

pool_end() {
	wait
	pool_f=0 pool_i=0
	while [ $pool_i -lt $pool_n ]; do
		pool_i=$((pool_i + 1))
		cat "$pool_dir/$pool_i.out"
		[ ! -e "$pool_dir/$pool_i.fail" ] || pool_f=1
	done
	exec 9>&-
	rm -rf "$pool_dir"
	return $pool_f
}
