#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

# proto-report: buf lint and buf breaking for the agent wire proto
# (proto/pb/service.proto in the working tree) against the same file at the
# git ref PROTO_BASELINE (default proto/v0.2.0, the first tag that holds it).
#
# REPORT mode (default): prints findings and counts, exits 0.
# PROTO_REPORT_STRICT=1: exits 1 on any breaking change (lint stays a report:
# the v0 proto fails STANDARD by design).
# Needs buf on PATH (or BUF=/path/to/buf); without it, says so and exits 0.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
buf="${BUF:-$(command -v buf || true)}"
baseline="${PROTO_BASELINE:-proto/v0.2.0}"
if [ -z "$buf" ]; then
	echo "proto-report: buf not found (install: https://buf.build/docs/installation, or BUF=/path/to/buf); skipped"
	exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/current" "$work/baseline"
cp "$root/proto/pb/buf.yaml" "$root/proto/pb/service.proto" "$work/current/"
cp "$root/proto/pb/buf.yaml" "$work/baseline/"
git -C "$root" show "$baseline:proto/pb/service.proto" >"$work/baseline/service.proto"

lint="$(cd "$work/current" && "$buf" lint --error-format=json 2>&1 || true)"
breaking="$(cd "$work/current" && "$buf" breaking --against "$work/baseline" 2>&1 || true)"

count() { if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l | tr -d ' '; fi; }
echo "== buf lint (STANDARD, COMMENTS) of proto/pb/service.proto: $(count "$lint") finding(s)"
printf '%s\n' "$lint" | sed -n 's/.*"type":"\([A-Z_]*\)".*/\1/p' | sort | uniq -c | sort -rn || true
echo "== buf breaking (FILE, WIRE_JSON) vs $baseline: $(count "$breaking") finding(s)"
[ -z "$breaking" ] || printf '%s\n' "$breaking"
if [ "${PROTO_REPORT_STRICT:-0}" = 1 ] && [ -n "$breaking" ]; then
	exit 1
fi
