#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

# check-semgrep.sh: semgrep with the Go rules of semgrep/semgrep-rules (the
# go/ tree that the p/golang and p/gosec registry packs draw from) over
# first-party Go code (.semgrepignore), gated by scripts/semgrep-baseline.txt
# through scripts/sast-baseline.py: fails on a finding not in the baseline
# and on a stale baseline entry (make check-semgrep). --update rewrites the
# baseline after triage.
#
# Pinned and offline-capable: the semgrep image by digest, the rules by
# commit and by the sha256 of their concatenated YAML. The rules are fetched
# once into ${SEMGREP_RULES_CACHE} (Semgrep Rules License v1.0: used, not
# redistributed, so not checked in); the scan runs with --network none and
# --metrics=off. Needs docker. SEMGREP_JSON (read this saved report instead
# of running the tool) is for reuse of one run. ~2 min.
set -euo pipefail

IMAGE="semgrep/semgrep:1.180.0@sha256:529ee8a277ec8adc5b534d7c74eea0a47e9de21d62852b6ba7ac6ba9566845c3" # 2026-10-07
RULES_COMMIT=a84ff9cc2453ca91d581380de4b8b3f272f6f4be # semgrep-rules develop, 2026-09-22
RULES_SHA256=679aebf66f3ece73b3e213015390294caa590dba0920a773ac669eec8b0c38e1
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="${SEMGREP_BASELINE:-${ROOT}/scripts/semgrep-baseline.txt}"
RULES="${SEMGREP_RULES_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/nfltr/semgrep-rules-${RULES_COMMIT}}"
mode=check
[[ "${1:-}" == "--update" ]] && mode=update
cd "${ROOT}"
python3 scripts/sast-baseline.py --self-test >/dev/null 2>&1 || { echo "FAIL: sast-baseline self-test" >&2; exit 1; }

rules_sum() { (cd "$1" && find go -name '*.yaml' | LC_ALL=C sort | xargs cat | shasum -a 256 | awk '{print $1}'); }
out="$(mktemp)"
trap 'rm -f "${out}"' EXIT
if [[ -n "${SEMGREP_JSON:-}" ]]; then
    cp "${SEMGREP_JSON}" "${out}"
else
    if [[ ! -d "${RULES}/go" ]]; then
        tmp="${RULES}.tmp.$$"
        mkdir -p "${tmp}"
        curl -fsSL "https://codeload.github.com/semgrep/semgrep-rules/tar.gz/${RULES_COMMIT}" |
            tar -xz -C "${tmp}" --strip-components=1 "semgrep-rules-${RULES_COMMIT}/go" "semgrep-rules-${RULES_COMMIT}/LICENSE"
        mv "${tmp}" "${RULES}"
    fi
    got="$(rules_sum "${RULES}")"
    [[ "${got}" == "${RULES_SHA256}" ]] || { echo "FAIL: ${RULES} rules sha256 ${got}, want ${RULES_SHA256}" >&2; exit 1; }
    docker run --rm --network none -v "${ROOT}:/src:ro" -v "${RULES}/go:/rules:ro" -w /src "${IMAGE}" \
        semgrep scan --metrics=off --disable-version-check --config /rules --no-git-ignore --timeout 0 --include '*.go' \
        --json --quiet >"${out}"
    [[ -z "${SEMGREP_REPORT:-}" ]] || cp "${out}" "${SEMGREP_REPORT}"
fi
python3 - "${out}" <<'EOF'
import json, sys
# An error, or a rule timing out on a file, means an incomplete scan.
errs = [e for e in json.load(open(sys.argv[1])).get("errors", []) if e.get("level") == "error" or e.get("type") == "Timeout"]
for e in errs[:20]:
    print("semgrep error:", e.get("type"), e.get("message", "")[:200], file=sys.stderr)
sys.exit(1 if errs else 0)
EOF
python3 scripts/sast-baseline.py "${mode}" semgrep "${out}" "${BASELINE}" "${ROOT}"
