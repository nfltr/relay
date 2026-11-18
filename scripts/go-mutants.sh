#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# go-mutants.sh <list> [mutant...]: plants each bug of a mutant list
# (<package>/testdata/<name>.txt, a path from the repository root; its
# lines "<mutant> | <file> | <exact line text> | <replacement> | <test>",
# the lines of one mutant applied together, each replacing one whole line
# of its file that occurs exactly once; a file outside the package is a
# path from it, e.g. ../internal/x/x.go) and checks that its test then
# fails. Fails on a mutant its test does not catch, or whose line is gone.
# A port of nfltr's scripts/orgpki-mutants.sh. make test-go-mutants.
# The tree is never edited: each mutant's files are written to a temp dir
# and given to go test as an -overlay, so mutants run in parallel
# (MUTANT_JOBS, default the CPUs the cgroup allows).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# one <list> <mutant> <outdir>: plant one mutant through an overlay and
# write its verdict line to <outdir>/<mutant> (first word caught, MISSED
# or FAIL).
if [[ "${1:-}" == "--one" ]]; then
  list="$2" m="$3" out="$4"
  pkg="$(dirname "$(dirname "$list")")"
  rel="${pkg#"$root"/}"
  module="${rel%%/*}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  test="" replace="" n=0
  while IFS= read -r line; do
    file="$(printf '%s' "$line" | awk -F ' [|] ' '{print $2}')"
    test="$(printf '%s' "$line" | awk -F ' [|] ' '{print $5}')"
    src="$(cd "$(dirname "$pkg/$file")" && pwd)/$(basename "$file")"
    # A second line of the same mutant on the same file edits its copy.
    dst="$(grep -F "\"$src\": " "$tmp/map" 2>/dev/null | sed 's/.*: "\(.*\)",$/\1/' || true)"
    if [[ -z "$dst" ]]; then
      n=$((n + 1))
      dst="$tmp/$n.go"
      cp "$src" "$dst"
      printf '"%s": "%s",\n' "$src" "$dst" >>"$tmp/map"
    fi
    ORIG="$(printf '%s' "$line" | awk -F ' [|] ' '{print $3}')" \
      REPL="$(printf '%s' "$line" | awk -F ' [|] ' '{print $4}')" \
      perl -i -ne 'BEGIN{$n=0} chomp; if ($_ eq $ENV{ORIG}) { $n++; print "$ENV{REPL}\n" } else { print "$_\n" } END{ exit($n == 1 ? 0 : 3) }' "$dst" ||
      { echo "FAIL $m: its line is not exactly once in $file: $(printf '%s' "$line" | awk -F ' [|] ' '{print $3}')" >"$out/$m"; exit 0; }
  done < <(grep "^$m [|] " "$list")
  [[ -n "$test" ]] || { echo "FAIL $m: no such mutant" >"$out/$m"; exit 0; }
  replace="$(sed '$ s/,$//' "$tmp/map")"
  printf '{"Replace": {\n%s\n}}\n' "$replace" >"$tmp/overlay.json"
  # Caught only when the test itself fails: a mutant that does not build
  # proves nothing.
  res="$(cd "$root/$module" && go test -overlay "$tmp/overlay.json" -count=1 -run "^${test}\$" "./${rel#"$module"/}/" 2>&1 || true)"
  if grep -q -- "--- FAIL: ${test} " <<<"$res"; then
    echo "caught $m: $test fails" >"$out/$m"
  else
    echo "MISSED $m: $test does not fail: $(tail -n 3 <<<"$res" | tr '\n' ' ')" >"$out/$m"
  fi
  exit 0
fi

list="$root/$1"
shift
pkg="$(dirname "$(dirname "$list")")"
rel="${pkg#"$root"/}"
module="${rel%%/*}"
# A list whose package, its dependencies, the list and this script are
# unchanged since it passed: its verdict from scripts/cicache.sh.
cicache="$root/scripts/cicache.sh"
deps="$(cd "$root/$module" && "$cicache" godeps "./${rel#"$module"/}")"
# shellcheck disable=SC2086 # deps: one path a line, no spaces
key="$("$cicache" key -v "go-mutants ${list#"$root"/} $*" -v "$(go version) $(go env GOOS GOARCH GOFLAGS GOEXPERIMENT CGO_ENABLED | tr '\n' ' ')" \
  "$list" "$root/scripts/go-mutants.sh" $deps)"
! "$cicache" get "$key" || exit 0

# The CPUs this process may use: a cgroup v2 quota (a CI container), else
# every online CPU.
jobs="${MUTANT_JOBS:-}"
if [[ -z "$jobs" ]]; then
  jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
  if { read -r q p </sys/fs/cgroup/cpu.max; } 2>/dev/null && [[ "$q" != max ]]; then
    jobs=$(((q + p - 1) / p))
  fi
fi

mutants="$(grep -v '^#' "$list" | grep -v '^$' | awk -F ' [|] ' '{print $1}' | uniq)"
[[ $# -eq 0 ]] || mutants="$*"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
# shellcheck disable=SC2086 # mutants: one name a line, no spaces
printf '%s\n' $mutants | xargs -P "$jobs" -I{} "$root/scripts/go-mutants.sh" --one "$list" {} "$out"
caught=0 missed=0 failed=0
for m in $mutants; do
  [[ -f "$out/$m" ]] || { echo "FAIL $m: no verdict" >&2; failed=1; continue; }
  case "$(cat "$out/$m")" in
  caught*) cat "$out/$m"; caught=$((caught + 1)) ;;
  MISSED*) cat "$out/$m"; missed=$((missed + 1)) ;;
  *) cat "$out/$m" >&2; failed=1 ;;
  esac
done
echo "caught $caught, missed $missed"
[[ $failed -eq 0 && $missed -eq 0 ]] || exit 1
echo "caught $caught, missed 0 ($rel ${list##*/})" | "$cicache" put "$key" || true
