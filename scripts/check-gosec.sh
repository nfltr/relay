#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

# check-gosec.sh: gosec (securego/gosec) over first-party Go code (vendor/,
# testdata, generated code and _test.go files excluded), gated by
# scripts/gosec-baseline.txt through scripts/sast-baseline.py: fails on a
# finding not in the baseline and on a stale baseline entry
# (make check-gosec). --update rewrites the baseline after triage.
#
# gosec is pinned (VERSION) and built once into ${GOSEC_CACHE} with
# golang.org/x/tools at XTOOLS: v2.29.0's own x/tools (v0.49.0) cannot read
# Go 1.27 export data ("function with type parameters cannot have a
# receiver") and silently skips every package importing math/rand/v2.
# The first build needs the module proxy; later runs are offline.
# GOSEC_JSON (read this saved report instead of running the tool) is for
# reuse of one run. ~3 min on a warm build cache.
set -euo pipefail

VERSION=v2.29.0 # released 2026-08-26
XTOOLS=v0.51.0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="${GOSEC_BASELINE:-${ROOT}/scripts/gosec-baseline.txt}"
GOSEC_CACHE="${GOSEC_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/nfltr/gosec-${VERSION}-xtools-${XTOOLS}}"
mode=check
[[ "${1:-}" == "--update" ]] && mode=update
cd "${ROOT}"
python3 scripts/sast-baseline.py --self-test >/dev/null 2>&1 || { echo "FAIL: sast-baseline self-test" >&2; exit 1; }

out="$(mktemp)"
trap 'rm -f "${out}"' EXIT
if [[ -n "${GOSEC_JSON:-}" ]]; then
    cp "${GOSEC_JSON}" "${out}"
else
    bin="${GOSEC_CACHE}/gosec"
    if ! go version -m "${bin}" 2>/dev/null | grep -q "github.com/securego/gosec/v2[[:space:]]*${VERSION}"; then
        mkdir -p "${GOSEC_CACHE}/src"
        printf 'module gosecbuild\n\ngo 1.27.0\n' >"${GOSEC_CACHE}/src/go.mod"
        printf '//go:build tools\n\npackage tools\n\nimport _ "github.com/securego/gosec/v2/cmd/gosec"\n' >"${GOSEC_CACHE}/src/tools.go"
        (cd "${GOSEC_CACHE}/src" && GOTOOLCHAIN="$(cd "${ROOT}" && go env GOVERSION)" GOFLAGS=-mod=mod \
            go get "github.com/securego/gosec/v2/cmd/gosec@${VERSION}" "golang.org/x/tools@${XTOOLS}" &&
            GOFLAGS=-mod=mod go build -o "${bin}" github.com/securego/gosec/v2/cmd/gosec)
    fi
    # One run per workspace module (gosec loads one module's ./...), merged.
    # Exit 1 = issues found; the baseline decides below.
    parts=()
    for mod in proto client; do
        part="$(mktemp)"
        parts+=("${part}")
        (cd "${ROOT}/${mod}" && "${bin}" -quiet -exclude-generated -exclude-dir=vendor \
            -exclude-dir=testdata -fmt=json -out="${part}" ./...) || [[ $? == 1 ]]
    done
    python3 -c 'import json,sys; print(json.dumps({"Issues": [i for f in sys.argv[1:] for i in (json.load(open(f)).get("Issues") or [])]}))' "${parts[@]}" >"${out}"
    rm -f "${parts[@]}"
    [[ -z "${GOSEC_REPORT:-}" ]] || cp "${out}" "${GOSEC_REPORT}"
fi
python3 scripts/sast-baseline.py "${mode}" gosec "${out}" "${BASELINE}" "${ROOT}"
