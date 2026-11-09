#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# go-mutants.sh <list> [mutant...]: plants each bug of a mutant list
# (<package>/testdata/<name>.txt, a path from the repository root; its
# lines "<mutant> | <file> | <exact line text> | <replacement> | <test>",
# the lines of one mutant applied together, each replacing one whole line
# of its file that occurs exactly once) and checks that its test then
# fails; the package's files are restored after each. Fails on a mutant
# its test does not catch, or whose line is gone. A port of nfltr's
# scripts/orgpki-mutants.sh. make test-go-mutants.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
list="$root/$1"
shift
pkg="$(dirname "$(dirname "$list")")"
rel="${pkg#"$root"/}"
module="${rel%%/*}"
backup="$(mktemp -d)"
cp "$pkg"/*.go "$backup/"
restore() { cp "$backup"/*.go "$pkg/"; }
trap 'restore; rm -rf "$backup"' EXIT

mutants="$(grep -v '^#' "$list" | grep -v '^$' | awk -F ' [|] ' '{print $1}' | uniq)"
[[ $# -eq 0 ]] || mutants="$*"
caught=0 missed=0
for m in $mutants; do
  test=""
  while IFS= read -r line; do
    file="$(printf '%s' "$line" | awk -F ' [|] ' '{print $2}')"
    test="$(printf '%s' "$line" | awk -F ' [|] ' '{print $5}')"
    ORIG="$(printf '%s' "$line" | awk -F ' [|] ' '{print $3}')" \
      REPL="$(printf '%s' "$line" | awk -F ' [|] ' '{print $4}')" \
      perl -i -ne 'BEGIN{$n=0} chomp; if ($_ eq $ENV{ORIG}) { $n++; print "$ENV{REPL}\n" } else { print "$_\n" } END{ exit($n == 1 ? 0 : 3) }' "$pkg/$file" ||
      { echo "FAIL $m: its line is not exactly once in $file: $(printf '%s' "$line" | awk -F ' [|] ' '{print $3}')" >&2; exit 1; }
  done < <(grep "^$m [|] " "$list")
  [[ -n "$test" ]] || { echo "FAIL $m: no such mutant" >&2; exit 1; }
  # Caught only when the test itself fails: a mutant that does not build
  # proves nothing.
  out="$(cd "$root/$module" && go test -count=1 -run "^${test}\$" "./${rel#"$module"/}/" 2>&1 || true)"
  if grep -q -- "--- FAIL: ${test} " <<<"$out"; then
    echo "caught $m: $test fails"
    caught=$((caught + 1))
  else
    echo "MISSED $m: $test does not fail: $(tail -n 3 <<<"$out" | tr '\n' ' ')"
    missed=$((missed + 1))
  fi
  restore
done
echo "caught $caught, missed $missed"
[[ $missed -eq 0 ]]
