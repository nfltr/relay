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
# (MUTANT_JOBS, default the job's share of the CPUs under make ci,
# CI_JOB_CPUS, else the CPUs the cgroup allows).
#
# go-mutants.sh --check <list>...: the static part alone, in seconds (make
# check-go-mutants, first in make ci's static job): every line has its five
# fields, its file exists, its exact line occurs exactly once (after the
# mutant's earlier lines on that file) and its test is a func of the
# package's _test.go files. A stale list fails here, not after the mutants.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${1:-}" == "--check" ]]; then
  shift
  cd "$root"
  exec perl -e '
    my $bad = 0;
    for my $list (@ARGV) {
      (my $pkg = $list) =~ s{/testdata/[^/]+$}{};
      open(my $fh, "<", $list) or do { print "FAIL $list: $!\n"; $bad = 1; next };
      my (%copy, %tests);
      while (my $l = <$fh>) {
        chomp $l;
        my $ln = $.;
        next if $l =~ /^#/ || $l eq "";
        my @f = split / [|] /, $l, -1;
        if (@f != 5) { print "FAIL $list:$ln: not five fields\n"; $bad = 1; next }
        my ($m, $file, $orig, $repl, $test) = @f;
        my $path = "$pkg/$file";
        unless (exists $copy{"$m\0$path"}) {
          open(my $src, "<", $path) or do { print "FAIL $list:$ln ($m): no file $file\n"; $bad = 1; next };
          chomp(my @lines = <$src>);
          $copy{"$m\0$path"} = \@lines;
        }
        my $n = 0;
        for (@{ $copy{"$m\0$path"} }) { if ($_ eq $orig) { $n++; $_ = $repl } }
        if ($n != 1) { print "FAIL $list:$ln ($m): its line is $n times in $file: $orig\n"; $bad = 1 }
        unless (%tests) {
          for my $t (glob("$pkg/*_test.go")) {
            open(my $tf, "<", $t) or next;
            while (<$tf>) { $tests{$1} = 1 if /^func (Test\w+)\(/ }
          }
          $tests{"\0"} = 1;
        }
        unless ($tests{$test}) { print "FAIL $list:$ln ($m): no func $test in $pkg/*_test.go\n"; $bad = 1 }
      }
    }
    print "go-mutants: ", scalar(@ARGV), " lists checked\n" unless $bad;
    exit $bad;
  ' "$@"
fi

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

# Else the CPUs this process may use: a cgroup v2 quota (a CI container),
# else every online CPU.
jobs="${MUTANT_JOBS:-${CI_JOB_CPUS:-}}"
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
