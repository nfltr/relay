#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# check-hadolint.sh: hadolint (pinned image) on every tracked Dockerfile
# outside vendor/, with .hadolint.yaml (failure threshold: warning) (make
# check-hadolint). The release image's digest pins (docker/Dockerfile) are
# checked in github.com/nfltr/hosted. Needs docker; offline once the image
# is pulled. ~15 s.
set -euo pipefail

IMAGE="hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d" # 2026-07-31
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

fail=0
while IFS= read -r f; do
    if ! out="$(docker run --rm -i -v "${ROOT}/.hadolint.yaml:/.config/hadolint.yaml:ro" "${IMAGE}" \
        hadolint --no-color --config /.config/hadolint.yaml - <"${f}" 2>&1)"; then
        echo "${out}" | sed "s|^-:|${f}:|"
        fail=1
    fi
done < <(git ls-files | grep -E '(^|/)Dockerfile(\.[^/]+)?$' | grep -vE '^vendor/')

[[ "${fail}" == 0 ]] && echo "check-hadolint: ok"
exit "${fail}"
