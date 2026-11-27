#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

# fuzz-short.sh: every Go fuzz target of the wire parsers and the SDK
# (the link frame and hello parsers are github.com/nfltr/link's),
# FUZZTIME each (default 10s; nightly FUZZTIME=10m). A crasher fails the run
# and go writes it to <package>/testdata/fuzz/<Target>/; commit it with the
# fix as a regression seed (it then runs in every plain `go test`).
# FUZZ_OUT=<file> also writes one "<package> <target> <exit status>" line per
# target.
# FUZZPARALLEL caps the workers per target (default: GOMAXPROCS).
set -uo pipefail
cd "$(dirname "$0")/.."
TARGETS=(
	"proto ./wire/wsframe FuzzReadMessage"
	"proto ./wire/wsframe FuzzFrameRoundTrip"
	"proto ./wire/dataplane FuzzParseWindow"
	"proto ./wire/dataplane FuzzUpgradeReply"
	"proto ./wire/dataplane FuzzReadAnswer"
	"proto ./wire/agentservices FuzzParse"
	"proto ./wire/hookwire FuzzOpen"
	"proto ./wire/grpccodec FuzzUnmarshalAliasingPayload"
	"client ./mailboxclient FuzzDecodeError"
	"client ./capaddr FuzzParse"
	"client ./nfnet FuzzParseTarget"
	"client ./dgram FuzzReadFrame"
)
# Every fuzz target of the repository, by package, is in TARGETS and
# nothing else is: go test -fuzz passes on a name that matches nothing.
want=$(grep -rHoE '^func Fuzz[A-Za-z0-9_]+' --include='*_test.go' . |
	sed -E 's|^\./||; s|/[^/]*:func | |' | LC_ALL=C sort)
have=$(for t in "${TARGETS[@]}"; do read -r mod pkg name <<<"$t"; echo "${mod}/${pkg#./} ${name}"; done | LC_ALL=C sort)
if [[ "$want" != "$have" ]]; then
	echo "fuzz-short: TARGETS differs from the repository's fuzz targets:" >&2
	diff <(echo "$have") <(echo "$want") >&2
	exit 1
fi
failed=0
for t in "${TARGETS[@]}"; do
	read -r mod pkg name <<<"$t"
	echo "── ${mod}/${pkg#./} ${name} (${FUZZTIME:-10s})"
	rc=0
	(cd "$mod" && go test -run '^$' -fuzz "^${name}\$" -fuzztime "${FUZZTIME:-10s}" -fuzzminimizetime 100x ${FUZZPARALLEL:+-parallel "${FUZZPARALLEL}"} "${pkg}") || rc=$?
	[[ -n "${FUZZ_OUT:-}" ]] && echo "${mod}/${pkg#./} ${name} ${rc}" >>"${FUZZ_OUT}"
	((rc == 0)) || failed=1
done
exit "${failed}"
