#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# cicache_test.sh: scripts/cicache.sh's soundness, per kind of check (TLC,
# ProVerif, Go mutants, through the scripts that use it): a change to any
# input misses, an unchanged input hits, a failure is never stored, and a
# key planted without one of its inputs is caught by CICACHE_VERIFY. No
# Java, no ProVerif: stand-ins count their runs. make test-cicache.
set -euo pipefail
src=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
export CICACHE_DIR=$t/cache
unset CICACHE CICACHE_VERIFY CICACHE_STAGE
fails=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
# expect NAME WANT GOT
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: got $3, want $2"; fi; }

r=$t/repo
mkdir -p "$r/scripts" "$r/spec/proverif"
cp "$src/scripts/cicache.sh" "$r/scripts/"
# The Go mutant runner: relay's go-mutants.sh <list>, or nfltr's
# MUTANTS_PKG=<package> orgpki-mutants.sh (go test -mod vendor).
for f in go-mutants.sh orgpki-mutants.sh; do [ ! -f "$src/scripts/$f" ] || cp "$src/scripts/$f" "$r/scripts/"; done
[ ! -f "$src/spec/proverif/run.sh" ] || cp "$src/spec/proverif/run.sh" "$r/spec/proverif/"
c=$r/scripts/cicache.sh

# --- key
echo a >"$r/a"
echo b >"$t/outside"
k1=$("$c" key -v x "$r/a" "$t/outside")
expect "key: same inputs, same key" "$k1" "$(cd "$r" && "$c" key -v x a "$t/outside")"
cp "$t/outside" "$t/outside2"
expect "key: a file outside the repository counts by content only" "$k1" "$("$c" key -v x "$r/a" "$t/outside2")"
echo A >"$r/a"
[ "$("$c" key -v x "$r/a" "$t/outside")" != "$k1" ] && ok "key: a changed file misses" || bad "key: a changed file hit"
[ "$("$c" key -v y "$r/a" "$t/outside")" != "$("$c" key -v x "$r/a" "$t/outside")" ] && ok "key: a changed string misses" || bad "key: a changed string hit"
"$c" key "$r/missing" >/dev/null 2>&1 && bad "key: a missing input passed" || ok "key: a missing input fails"

# --- TLC: a stand-in java counting its runs; its exit status is the
# content of $t/verdict (an input no key names: the planted wrong key).
s=$r/spec
cat >"$t/java" <<EOF
#!/bin/sh
echo run >>"$t/runs"
echo "Finished in 1s at (x)"
exit \$(cat "$t/verdict" 2>/dev/null || echo 0)
EOF
chmod +x "$t/java"
echo jar1 >"$t/tla2tools.jar"
printf -- '---- MODULE A ----\nEXTENDS Naturals, B\n====\n' >"$s/A.tla"
printf -- '---- MODULE B ----\n====\n' >"$s/B.tla"
printf -- '---- MODULE C ----\n====\n' >"$s/C.tla"
printf 'INIT Init\nNEXT Next\n' >"$s/A.cfg"
# tlc [STATUS]: one TLC run of A.cfg through the cache in a script that
# ends with STATUS (default 0); prints the runs the stand-in made.
tlc() {
	: >"$t/runs"
	stage=$("$c" begin)
	(cd "$s" && CICACHE_STAGE=$stage "$c" tlc -- "$t/java" -XX:+UseParallelGC -cp "$t/tla2tools.jar" tlc2.TLC -workers 2 \
		-metadir "$t/states.$RANDOM" -config "${CFG:-A.cfg}" A.tla >"$t/out" 2>&1) && st=0 || st=$?
	"$c" end "$stage" "${1:-$st}" 2>"$t/end" || echo mismatch >>"$t/runs"
	wc -l <"$t/runs" | tr -d ' '
}
expect "tlc: first run runs" 1 "$(tlc)"
expect "tlc: unchanged inputs hit (another metadir)" 0 "$(tlc)"
grep -q '^Finished in' "$t/out" && ok "tlc: a hit replays TLC's output" || bad "tlc: a hit did not replay the output"
echo '\* edit' >>"$s/B.tla"
expect "tlc: a changed module it extends misses" 1 "$(tlc)"
echo '\* edit' >>"$s/C.tla"
expect "tlc: a changed module it does not name hits" 0 "$(tlc)"
echo '\* edit' >>"$s/A.tla"
expect "tlc: a changed .tla line misses" 1 "$(tlc)"
echo 'INVARIANT TypeOK' >>"$s/A.cfg"
expect "tlc: a changed .cfg misses" 1 "$(tlc)"
echo jar2 >"$t/tla2tools.jar"
expect "tlc: another tla2tools.jar misses" 1 "$(tlc)"
echo '\* edit' >>"$s/A.tla"
expect "tlc: a failed script stores nothing" 1 "$(tlc 1)"
expect "tlc: so the next run runs" 1 "$(tlc)"
echo '\* edit' >>"$s/A.tla"
echo 12 >"$t/verdict"
expect "tlc: a violation of a passing script is stored" 1 "$(tlc 0)"
expect "tlc: and replayed with its exit status" 0 "$(tlc 0)"
(cd "$s" && CICACHE_STAGE=$("$c" begin) "$c" tlc -- "$t/java" -cp "$t/tla2tools.jar" -config A.cfg A.tla >/dev/null 2>&1) && bad "tlc: replayed exit 0" || ok "tlc: replayed exit status 12"
rm "$t/verdict"
# A module from -DTLA-Library (relay-core's specs extend link's).
mkdir -p "$t/lib"
printf -- '---- MODULE L ----\n====\n' >"$t/lib/L.tla"
printf -- '---- MODULE D ----\nEXTENDS L\n====\n' >"$s/D.tla"
# libtlc: one run of D through the cache; prints the stand-in's runs.
libtlc() {
	: >"$t/runs"
	stage=$("$c" begin)
	(cd "$s" && CICACHE_STAGE=$stage "$c" tlc -- "$t/java" -DTLA-Library="$t/lib" -cp "$t/tla2tools.jar" tlc2.TLC -config A.cfg D.tla >/dev/null 2>&1)
	"$c" end "$stage" 0 2>/dev/null
	wc -l <"$t/runs" | tr -d ' '
}
libtlc >/dev/null
expect "tlc: a library module unchanged hits" 0 "$(libtlc)"
echo '\* edit' >>"$t/lib/L.tla"
expect "tlc: a changed library module misses" 1 "$(libtlc)"
# A model that loads a module reading files is never cached; one that only
# names such a module in a comment is.
printf -- '---- MODULE R ----\nx == ndJsonDeserialize("t")\n====\n' >"$s/R.tla"
printf -- '---- MODULE A ----\nEXTENDS Naturals, B\n(* see R *)\n====\n' >"$s/A.tla"
tlc >/dev/null
expect "tlc: a module named only in a comment does not make a model uncached" 0 "$(tlc)"
printf -- '---- MODULE A ----\nEXTENDS Naturals,\n  B, R\n====\n' >"$s/A.tla"
tlc >/dev/null
expect "tlc: a model extending a module that reads a file is never cached" 1 "$(tlc)"
printf -- '---- MODULE A ----\nEXTENDS Naturals, B\n\\* restored\n====\n' >"$s/A.tla"
printf 'CONSTANT TraceFile = "%s/trace.ndjson"\n' "$t" >"$s/T.cfg"
CFG=T.cfg tlc >/dev/null
expect "tlc: a config naming a file (a trace) is never cached" 1 "$(CFG=T.cfg tlc)"
echo '\* edit' >>"$s/A.tla"
expect "tlc: CICACHE=off runs" 1 "$(CICACHE=off tlc)"
expect "tlc: and stores nothing" 1 "$(tlc)"
# The planted wrong key: the verdict file changes, no key input does.
echo 12 >"$t/verdict"
expect "tlc: a planted wrong key hits without VERIFY" 0 "$(tlc)"
expect "tlc: CICACHE_VERIFY=1 reruns it and fails on the mismatch" 2 "$(CICACHE_VERIFY=1 tlc)"
grep -q 'VERIFY MISMATCH' "$t/end" && ok "tlc: the mismatch is reported" || bad "tlc: no mismatch report"
rm "$t/verdict"

# --- ProVerif: spec/proverif/run.sh one, a stand-in proverif.
p=$r/spec/proverif
if [ -f "$p/run.sh" ]; then
echo pin >"$r/scripts/fetch-proverif.sh"
cat >"$t/proverif" <<EOF
#!/bin/sh
echo run >>"$t/runs"
echo "RESULT event(x) is \$(cat "$t/pv" 2>/dev/null || echo true)."
EOF
chmod +x "$t/proverif"
cp "$t/proverif" "$t/proverif-other"
printf 'process 0\n' >"$p/m.pv"
mkdir -p "$t/pvout"
# pv [PROVERIF]: one run.sh one m - T; prints the stand-in's runs, or FAIL.
pv() {
	: >"$t/runs"
	(cd "$p" && PROVERIF=${1:-$t/proverif} PROVERIF_OUT=$t/pvout sh ./run.sh one m - T >"$t/out" 2>&1) || echo FAIL >>"$t/runs"
	tr '\n' ' ' <"$t/runs" | sed 's/ $//'
}
expect "proverif: first run runs" run "$(pv)"
expect "proverif: unchanged model hits" "" "$(pv)"
grep -q '^cached: ok   m \[-\] T' "$t/out" && ok "proverif: a hit prints the verdict line" || bad "proverif: hit printed $(cat "$t/out")"
printf 'process 0 (* edit *)\n' >"$p/m.pv"
expect "proverif: a changed .pv line misses" run "$(pv)"
expect "proverif: another proverif misses" run "$(pv "$t/proverif-other")"
echo false >"$t/pv"
printf 'process 0 (* edit 2 *)\n' >"$p/m.pv"
expect "proverif: a failure is not stored" "run FAIL" "$(pv)"
expect "proverif: so it runs again" "run FAIL" "$(pv)"
rm "$t/pv"
pv >/dev/null
echo false >"$t/pv"
expect "proverif: a planted wrong key hits without VERIFY" "" "$(pv)"
expect "proverif: CICACHE_VERIFY=1 reruns it and fails" "run FAIL" "$(CICACHE_VERIFY=1 pv)"
rm "$t/pv"
else
	echo "skip proverif: no spec/proverif/run.sh"
fi

# --- Go mutants: scripts/go-mutants.sh on a two-package module.
if command -v go >/dev/null && ls "$r"/scripts/*mutants.sh >/dev/null 2>&1; then
	g=$r/m
	[ -f "$r/scripts/go-mutants.sh" ] || g=$r # orgpki-mutants.sh: the module is the repository
	mkdir -p "$g/p/testdata" "$g/q" "$g/u"
	printf 'module example.com/m\n\ngo 1.22\n' >"$g/go.mod"
	mkdir -p "$g/vendor" && : >"$g/vendor/modules.txt"
	printf 'package q\n\nfunc One() int { return 1 }\n' >"$g/q/q.go"
	printf 'package u\n\nfunc U() {}\n' >"$g/u/u.go"
	printf 'package p\n\nimport "example.com/m/q"\n\nfunc Two() int {\n\treturn q.One() + 1\n}\n' >"$g/p/p.go"
	printf 'package p\n\nimport "testing"\n\nfunc TestTwo(t *testing.T) {\n\tif Two() != 2 {\n\t\tt.Fatal(Two())\n\t}\n}\n' >"$g/p/p_test.go"
	printf 'plus | p.go | \treturn q.One() + 1 | \treturn q.One() - 1 | TestTwo\n' >"$g/p/testdata/mutants.txt"
	# gm: one go-mutants.sh run; prints its go test runs (1: ran), or FAIL.
	gm() {
		if [ -f "$r/scripts/go-mutants.sh" ]; then
			(cd "$r" && GOWORK=off ./scripts/go-mutants.sh m/p/testdata/mutants.txt >"$t/out" 2>&1) || { echo FAIL; return; }
		else
			(cd "$r" && GOWORK=off MUTANTS_PKG=p ./scripts/orgpki-mutants.sh >"$t/out" 2>&1) || { echo FAIL; return; }
		fi
		grep -c '^caught plus' "$t/out" || true
	}
	expect "go-mutants: first run runs" 1 "$(gm)"
	expect "go-mutants: unchanged package hits" 0 "$(gm)"
	grep -q '^cached: caught 1, missed 0' "$t/out" && ok "go-mutants: a hit prints the verdict line" || bad "go-mutants: hit printed $(cat "$t/out")"
	printf '// edit\n' >>"$g/q/q.go"
	expect "go-mutants: a changed dependency misses" 1 "$(gm)"
	printf '// edit\n' >>"$g/u/u.go"
	expect "go-mutants: a changed package it does not import hits" 0 "$(gm)"
	printf '// edit\n' >>"$g/p/p.go"
	expect "go-mutants: a changed mutated file misses" 1 "$(gm)"
	printf 'x\n' >"$g/p/testdata/data.txt"
	expect "go-mutants: a changed testdata file misses" 1 "$(gm)"
	printf '\n' >>"$g/go.mod"
	expect "go-mutants: a changed go.mod misses" 1 "$(gm)"
	expect "go-mutants: another GOFLAGS (tool settings) misses" 1 "$(GOFLAGS=-tags=x gm)"
	printf 'missed | p.go | \treturn q.One() + 1 | \treturn q.One() + 1 // same | TestTwo\n' >>"$g/p/testdata/mutants.txt"
	expect "go-mutants: a changed list misses, a missed mutant fails" FAIL "$(gm)"
	expect "go-mutants: and is not stored" FAIL "$(gm)"
else
	echo "skip go-mutants: no go or no mutant runner"
fi

[ $fails = 0 ] && echo "cicache_test: ok" || { echo "cicache_test: $fails failed"; exit 1; }
