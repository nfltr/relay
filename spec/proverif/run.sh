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
# A mutant's line (it reads F or ? where its base reads T; its base is the
# line with its flags but the last, else "-") runs only the queries whose
# results differ from its base's: each query is proved on its own, and the
# base's line proves the rest. PROVERIF_FULL=1 (nightly, make spec-traces)
# runs every query of every line. A variant whose witnesses turn reachable
# (F where "-" reads T) is no mutant: its line ends "full".
set -eu
cd "$(dirname "$0")"
if [ "${1:-}" = one ]; then
	model=$2 flags=$3 want=$4 keep=${5:--}
	tag=$(echo "$model.$flags" | tr ',' '_')
	awk -v flags=",$flags," '{
		keep = 1
		i = index($0, "(* ONLY:"); if (i) { f = substr($0, i + 8); sub(/ .*/, "", f); if (index(flags, "," f ",") == 0) keep = 0 }
		i = index($0, "(* NOT:"); if (i) { f = substr($0, i + 7); sub(/ .*/, "", f); if (index(flags, "," f ",") != 0) keep = 0 }
		if (keep) print }' "$model.pv" >"$PROVERIF_OUT/$tag.pv"
	# keep: the query declarations to run (",3,7,"), when the model has one
	# per result.
	if [ "$keep" != - ] && [ "$(grep -c '^query[[:space:]]' "$PROVERIF_OUT/$tag.pv")" = ${#want} ]; then
		awk -v keep="$keep" '/^query[ \t]/ { n++; inq = 1; drop = !index(keep, "," n ",") }
			!(inq && drop) { print }
			inq && /\.[ \t]*(\(\*.*\*\))?[ \t]*$/ { inq = 0 }' "$PROVERIF_OUT/$tag.pv" >"$PROVERIF_OUT/$tag.sub"
		mv "$PROVERIF_OUT/$tag.sub" "$PROVERIF_OUT/$tag.pv"
		want=$(echo "$want" | awk -v keep="$keep" '{ for (i = 1; i <= length($0); i++) if (index(keep, "," i ",")) printf "%s", substr($0, i, 1); print "" }')
		flags="$flags $keep"
	fi
	# A model, its flags and want already proved with this ProVerif and
	# this script: its verdict from scripts/cicache.sh.
	k=$(../../scripts/cicache.sh key -v "proverif $flags $want" -v "$PROVERIF" "$PROVERIF_OUT/$tag.pv" run.sh ../../scripts/fetch-proverif.sh)
	! ../../scripts/cicache.sh get "$k" || exit 0
	start=$(date +%s)
	if ! "$PROVERIF" "$PROVERIF_OUT/$tag.pv" >"$PROVERIF_OUT/$tag.log" 2>&1; then
		echo "FAIL $model [$flags]: proverif exited non-zero, see $PROVERIF_OUT/$tag.log"
		exit 1
	fi
	got=$(grep '^RESULT [^(]' "$PROVERIF_OUT/$tag.log" | sed -e 's/.* is true\.$/T/' -e 's/.* is false\.$/F/' -e 's/.*cannot be proved\.$/?/' | tr -d '\n')
	secs=$(($(date +%s) - start))
	if awk -v g="$got" -v w="$want" 'BEGIN { if (length(g) != length(w)) exit 1
		for (i = 1; i <= length(w); i++) { c = substr(w, i, 1); if (c != "X" && c != substr(g, i, 1)) exit 1 } }'; then
		echo "ok   $model [$flags] $got (${secs}s)" | tee "$PROVERIF_OUT/$tag.ok"
		../../scripts/cicache.sh put "$k" <"$PROVERIF_OUT/$tag.ok" || true
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
	awk -v m="${1:-}" -v full="${PROVERIF_FULL:-}" '{ want[$1 " " $2] = $3; line[NR] = $1 " " $2 " " $3; mod[NR] = $1; fl[NR] = $2; w[NR] = $3; all[NR] = $4 == "full" }
	END { for (r = 1; r <= NR; r++) {
		if (m != "" && mod[r] != m) continue
		keep = "-"
		if (full == "" && fl[r] != "-" && !all[r]) {
			b = fl[r]; sub(/,?[^,]*$/, "", b); if (b == "" || !((mod[r] " " b) in want)) b = "-"
			bw = want[mod[r] " " b]; mut = 0; k = ","
			if (length(bw) == length(w[r])) for (i = 1; i <= length(bw); i++) {
				c = substr(w[r], i, 1); d = substr(bw, i, 1)
				if (c != d) { k = k i ","; if (d == "T") mut = 1 } }
			if (mut) keep = k }
		print line[r], keep } }' |
	xargs -P "$jobs" -L 1 sh ./run.sh one || { echo "spec-proverif: FAIL (logs in $PROVERIF_OUT)"; exit 1; }
echo "spec-proverif: ok"
