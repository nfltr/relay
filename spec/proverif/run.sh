#!/bin/sh
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
# run.sh [model] checks the ProVerif models (README.md): each line of
# expect.txt (PROVERIF_EXPECT) is "<model> <flags> <results>"; the model is
# run with those flags (a line ending "(* ONLY:f *)" is kept only with flag
# f, one ending "(* NOT:f *)" only without it; "-" is no flag) and its
# RESULT lines, in order, must read <results>: T true, F false (an attack;
# a witness reads F when its event is reachable), ? not proved, X not
# judged. Lines run side by side, PROVERIF_JOBS (default: the CPUs) at a
# time; logs and the generated models go to PROVERIF_OUT (default a temp
# dir). Exit 1 on any difference.
set -eu
cd "$(dirname "$0")"
if [ "${1:-}" = one ]; then
	model=$2 flags=$3 want=$4
	tag=$(echo "$model.$flags" | tr ',' '_')
	awk -v flags=",$flags," '{
		keep = 1
		i = index($0, "(* ONLY:"); if (i) { f = substr($0, i + 8); sub(/ .*/, "", f); if (index(flags, "," f ",") == 0) keep = 0 }
		i = index($0, "(* NOT:"); if (i) { f = substr($0, i + 7); sub(/ .*/, "", f); if (index(flags, "," f ",") != 0) keep = 0 }
		if (keep) print }' "$model.pv" >"$PROVERIF_OUT/$tag.pv"
	start=$(date +%s)
	if ! "$PROVERIF" "$PROVERIF_OUT/$tag.pv" >"$PROVERIF_OUT/$tag.log" 2>&1; then
		echo "FAIL $model [$flags]: proverif exited non-zero, see $PROVERIF_OUT/$tag.log"
		exit 1
	fi
	got=$(grep '^RESULT [^(]' "$PROVERIF_OUT/$tag.log" | sed -e 's/.* is true\.$/T/' -e 's/.* is false\.$/F/' -e 's/.*cannot be proved\.$/?/' | tr -d '\n')
	secs=$(($(date +%s) - start))
	if awk -v g="$got" -v w="$want" 'BEGIN { if (length(g) != length(w)) exit 1
		for (i = 1; i <= length(w); i++) { c = substr(w, i, 1); if (c != "X" && c != substr(g, i, 1)) exit 1 } }'; then
		echo "ok   $model [$flags] $got (${secs}s)"
		exit 0
	fi
	echo "FAIL $model [$flags]: got $got, want $want (${secs}s), see $PROVERIF_OUT/$tag.log"
	exit 1
fi

PROVERIF=$(../../scripts/fetch-proverif.sh)
PROVERIF_OUT=${PROVERIF_OUT:-$(mktemp -d)}
export PROVERIF PROVERIF_OUT
mkdir -p "$PROVERIF_OUT"
jobs=${PROVERIF_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}
grep -v '^[[:space:]]*\(#\|$\)' "${PROVERIF_EXPECT:-expect.txt}" |
	awk -v m="${1:-}" 'm == "" || $1 == m' |
	xargs -P "$jobs" -L 1 sh ./run.sh one || { echo "spec-proverif: FAIL (logs in $PROVERIF_OUT)"; exit 1; }
echo "spec-proverif: ok"
