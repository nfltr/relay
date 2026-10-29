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
set -uo pipefail
cd "$(dirname "$0")/.."
TARGETS=(
	"proto ./wire/wsframe FuzzReadMessage"
	"proto ./wire/wsframe FuzzFrameRoundTrip"
	"proto ./wire/dataplane FuzzSendRecvRoundTrip"
	"proto ./wire/dataplane FuzzParseWindow"
	"proto ./wire/dataplane FuzzUpgradeReply"
	"proto ./wire/dataplane FuzzReadAnswer"
	"proto ./wire/agentservices FuzzParse"
	"proto ./wire/blobwire FuzzParseContentRange"
	"proto ./wire/blobwire FuzzParseDigest"
	"client ./mailboxclient FuzzDecodeError"
	"client ./rpcclient FuzzA2AE2EE0RTTAccept"
)
failed=0
for t in "${TARGETS[@]}"; do
	read -r mod pkg name <<<"$t"
	echo "── ${mod}/${pkg#./} ${name} (${FUZZTIME:-10s})"
	rc=0
	(cd "$mod" && go test -run '^$' -fuzz "^${name}\$" -fuzztime "${FUZZTIME:-10s}" -fuzzminimizetime 100x "${pkg}") || rc=$?
	[[ -n "${FUZZ_OUT:-}" ]] && echo "${mod}/${pkg#./} ${name} ${rc}" >>"${FUZZ_OUT}"
	((rc == 0)) || failed=1
done
exit "${failed}"
