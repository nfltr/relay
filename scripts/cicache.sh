#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# cicache.sh: a content-addressed cache of deterministic check results (TLC
# runs, ProVerif models, Go mutant lists), so make ci never re-checks what
# did not change. The same file in every nfltr repository; its test is
# scripts/cicache_test.sh. A key is the sha256 of exactly the inputs a
# check reads (file contents, repository-relative paths) and its command
# line and tool versions; only a passing verdict is stored, never a
# failure. Entries live in CICACHE_DIR (default
# ${XDG_CACHE_HOME:-~/.cache}/nfltr-cicache: on the Linux runners a
# directory all runners of a machine share), written by atomic rename.
# CICACHE=off: no reads, no writes. CICACHE_VERIFY=N: a hit whose key falls
# in 1 of N (1: every hit) is run again and must reach the same verdict
# (nightly: a key that leaves out an input shows up as a mismatch).
#
#   key [-v STRING]... FILE...  the key of these strings and files' contents
#   get KEY            print a stored verdict ("cached: <line>"), exit 0; exit 1
#                      on a miss (or a hit sampled by CICACHE_VERIFY)
#   put KEY            store stdin as KEY's passing verdict
#   godeps PKG         (in the package's module) the files a Go package's
#                      tests build from: every non-standard, non-module-cache
#                      dependency's directory files, embeds and go.mod, its
#                      testdata, go.work, and a file naming each module-cache
#                      dependency's module@version
#   begin              print a new staging directory (empty when CICACHE=off)
#   tlc -- JAVA ARGS...  run TLC (in the spec's directory) through the cache:
#                      key = the config, every module of that directory the
#                      model names (transitively), the classpath jars, the
#                      java path and every argument but -metadir's; staged in
#                      CICACHE_STAGE (no CICACHE_STAGE: plain run). TLC's
#                      verdict is the caller's to judge: its output and exit
#                      status are replayed as they were.
#   end STAGE STATUS   commit STAGE's TLC results when STATUS is 0 (the whole
#                      script passed, so no stored output led to a failure);
#                      exit 1 on a CICACHE_VERIFY mismatch in it
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
rootl=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)
dir=${CICACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/nfltr-cicache}
off() { [ "${CICACHE:-}" = off ]; }
sha() { shasum -a 256 | cut -c1-64; }

# verifying KEY: this hit is to be run again (CICACHE_VERIFY).
verifying() {
	local n=${CICACHE_VERIFY:-0}
	[ "$n" -gt 0 ] 2>/dev/null || return 1
	[ $((0x${1:0:7} % n)) = 0 ]
}

key() {
	local v="" f p fs=() here
	here=$(pwd -P)
	while [ $# -gt 0 ]; do
		case $1 in
		-v) v="$v
v $2"; shift 2 ;;
		*)
			[ -f "$1" ] || { echo "cicache: no such input file: $1" >&2; exit 2; }
			case $1 in /*) p=$1 ;; *) p=$here/$1 ;; esac
			p=${p#"$root"/}
			fs+=("${p#"$rootl"/}")
			shift ;;
		esac
	done
	# One shasum for every file (a Go package's dependencies are thousands);
	# a file outside the repository counts by its content only.
	{
		echo "cicache/1$v"
		[ ${#fs[@]} = 0 ] || (cd "$root" && printf '%s\0' "${fs[@]}" | xargs -0 shasum -a 256 --) |
			while read -r h f; do case $f in /*) f=ext ;; esac; echo "f $f $h"; done
	} | sha
}

entry() { echo "$dir/$1/${2:0:2}/$2"; }

# store FILE CLASS KEY: FILE renamed into place (same filesystem: atomic).
store() {
	local e
	e=$(entry "$2" "$3")
	mkdir -p "$(dirname "$e")"
	mv -f "$1" "$e"
}

get() {
	local e
	e=$(entry v "$1")
	! off && [ -f "$e" ] || return 1
	if verifying "$1"; then
		echo "cicache: verifying cached pass $1" >&2
		return 1
	fi
	touch "$e"
	sed 's/^/cached: /' "$e"
}

put() {
	local t
	off && { cat >/dev/null; return 0; }
	mkdir -p "$dir/tmp"
	t=$(mktemp "$dir/tmp/put.XXXXXX")
	cat >"$t"
	store "$t" v "$1"
}

godeps() {
	local mc d m f e x
	mc=$(go env GOMODCACHE)
	mkdir -p "$dir/tmp"
	x=$(mktemp "$dir/tmp/godeps.XXXXXX")
	# Each module-cache dependency by its module@version directory (the
	# cache's content is immutable, checked against go.sum on download);
	# every other one (this repository, vendor/, a replace) by its files and
	# its module's go.mod (the language version).
	go list -deps -test -f '{{if not .Standard}}{{.Dir}}{{"\t"}}{{with .Module}}{{.GoMod}}{{end}}{{"\t"}}{{join .EmbedFiles " "}} {{join .TestEmbedFiles " "}}{{end}}' "$@" |
		sort -u | while IFS="$(printf '\t')" read -r d m f; do
		[ -n "$d" ] || continue
		case $d in "$mc"/*) echo "${d#"$mc"/}" >>"$x"; continue ;; esac
		find "$d" -maxdepth 1 -type f
		[ -z "$m" ] || [ ! -f "$m" ] || echo "$m"
		for e in $f; do echo "$d/$e"; done
	done | sort -u
	for p in "$@"; do
		d=$(go list -f '{{.Dir}}' "$p")
		[ ! -d "$d/testdata" ] || find "$d/testdata" -type f
	done
	d=$(go env GOWORK)
	case $d in "" | off) ;; *) echo "$d" ;; esac
	echo "$x"
}

begin() {
	off && return 0
	mkdir -p "$dir/tmp"
	find "$dir/tmp" -mindepth 1 -maxdepth 1 -mtime +1 -exec rm -rf {} + 2>/dev/null || true
	mktemp -d "$dir/tmp/stage.XXXXXX"
}

end() {
	local s=$1 st=$2 f bad=0
	[ -n "$s" ] && [ -d "$s" ] || return 0
	echo "cicache: $(cat "$s/hits" 2>/dev/null | wc -l | tr -d ' ') TLC runs from the cache, $(cat "$s/runs" 2>/dev/null | wc -l | tr -d ' ') run" >&2
	if [ -s "$s/MISMATCH" ]; then
		cat "$s/MISMATCH" >&2
		bad=1
	elif [ "$st" = 0 ]; then
		for f in "$s"/tlc.*; do
			[ -f "$f" ] || continue
			store "$f" tlc "${f##*/tlc.}"
		done
	fi
	rm -rf "$s"
	return $bad
}

# modules DIRS MOD [precise]: MOD.tla and every module it names,
# transitively, each from the first of DIRS (colon-separated: the spec's
# directory, then -DTLA-Library's) that has it. By default any name counts,
# a comment's too (the key: more inputs, never fewer); precise: only the
# names of EXTENDS and INSTANCE outside comments (what the model loads).
# Standard modules are tla2tools.jar's.
modules() {
	local dirs todo seen m n d f
	IFS=: read -r -a dirs <<<"$1"
	todo=$2 seen=" "
	while [ -n "$todo" ]; do
		m=${todo%% *}
		todo=${todo#"$m"}
		todo=${todo# }
		case $seen in *" $m "*) continue ;; esac
		seen="$seen$m "
		f=
		for d in "${dirs[@]}"; do [ -n "$f" ] || [ ! -f "$d/$m.tla" ] || f=$d/$m.tla; done
		[ -n "$f" ] || continue
		echo "$f"
		for n in $(if [ -n "${3:-}" ]; then refs "$f"; else grep -oE '[A-Za-z0-9_]+' "$f" | sort -u; fi); do
			for d in "${dirs[@]}"; do
				[ ! -f "$d/$n.tla" ] || { todo="$todo $n"; break; }
			done
		done
		todo=${todo# }
	done
}

# refs FILE: the modules a .tla file's EXTENDS and INSTANCE name.
refs() {
	perl -0777 -ne 's/\(\*.*?\*\)//gs; s/\\\*[^\n]*//g;
		while (/\bEXTENDS\s+(\w+(?:\s*,\s*\w+)*)/g) { print "$_\n" for split /\s*,\s*/, $1 }
		while (/\bINSTANCE\s+(\w+)/g) { print "$1\n" }' "$1" | sort -u
}

tlc() {
	[ "${1:-}" = -- ] && shift
	local argv=("$@") args=() files=() mods=() a mod="" cfg="" lib=. out rc e k t j cp
	[ -n "${CICACHE_STAGE:-}" ] && ! off || exec "$@"
	args+=(-v "java $1")
	shift
	while [ $# -gt 0 ]; do
		a=$1
		shift
		case $a in
		-metadir) shift ;;
		-cp | -classpath)
			IFS=: read -r -a cp <<<"$1"
			for j in "${cp[@]}"; do files+=("$j"); done
			args+=(-v "$a")
			shift ;;
		-config) cfg=$1; files+=("$1"); args+=(-v "$a"); shift ;;
		-DTLA-Library=*) lib=.:${a#-DTLA-Library=} ;; # its modules count by content
		-dump | -userFile | -simulate | -generate) exec "${argv[@]}" ;;
		*.tla) mod=$a; args+=(-v "$a") ;;
		*) args+=(-v "$a") ;;
		esac
	done
	# A model reading a file at run time (a trace) has an input the key
	# cannot see: run it plainly.
	[ -n "$mod" ] && [ -n "$cfg" ] && [ -f "$cfg" ] || exec "${argv[@]}"
	! grep -q -e TraceFile -e '"/' "$cfg" || exec "${argv[@]}"
	while IFS= read -r a; do mods+=("$a"); done < <(modules "$lib" "${mod%.tla}")
	[ ${#mods[@]} -gt 0 ] || exec "${argv[@]}"
	! grep -q -e Deserialize -e IOExec $(modules "$lib" "${mod%.tla}" precise) || exec "${argv[@]}"
	k=$(key "${args[@]}" "${files[@]}" "${mods[@]}")
	e=$(entry tlc "$k")
	if [ -f "$e" ] && ! verifying "$k"; then
		touch "$e"
		echo "cicache: hit $mod $k" >&2
		echo "$mod" >>"$CICACHE_STAGE/hits"
		replay "$e"
		return
	fi
	out=$(mktemp "$CICACHE_STAGE/run.XXXXXX")
	rc=0
	echo "$mod" >>"$CICACHE_STAGE/runs"
	"${argv[@]}" >"$out.o" 2>"$out.e" || rc=$?
	if [ -f "$e" ]; then # verifying
		t=$(sed -n 1p "$e")
		[ "$t" = "$rc" ] || echo "cicache: VERIFY MISMATCH: TLC $mod (key $k): cached exit $t, rerun exit $rc" >>"$CICACHE_STAGE/MISMATCH"
	fi
	# Only a run TLC finished is a result (not a crash, an out of memory).
	if grep -q '^Finished in' "$out.o"; then
		{ echo "$rc"; wc -c <"$out.o" | tr -d ' '; cat "$out.o" "$out.e"; } >"$out.s"
		mv -f "$out.s" "$CICACHE_STAGE/tlc.$k" # runs side by side may share a key
	fi
	cat "$out.o"
	cat "$out.e" >&2
	rm -f "$out" "$out.o" "$out.e"
	return $rc
}

# replay ENTRY: a stored TLC run's stdout, stderr and exit status.
replay() {
	local rc n
	rc=$(sed -n 1p "$1")
	n=$(sed -n 2p "$1")
	tail -n +3 "$1" | head -c "$n"
	tail -n +3 "$1" | tail -c +$((n + 1)) >&2
	return "$rc"
}

cmd=${1:-}
shift || true
case $cmd in
key | get | put | godeps | begin | end | tlc | refs) $cmd "$@" ;;
*) echo "usage: cicache.sh key|get|put|godeps|begin|tlc|end ..." >&2; exit 2 ;;
esac
