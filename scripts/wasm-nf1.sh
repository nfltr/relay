#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# wasm-nf1.sh: the nf1 handshake as a browser runs it (client/nf1/internal/
# jsclient), built for GOOS=js GOARCH=wasm reproducibly: the toolchain go.work
# pins, -trimpath, no VCS stamp; built twice (the second from source, -a) and
# both hashes equal. Fails when the build links the relay dial (gRPC, the data
# plane, QUIC, link), when it is over budget (raw and gzip -9 -n bytes), or
# when it does not run one session under node. Prints its sha256 and sizes.
# nfltr docs/decisions/browser-peer-2026-11-16.md, lane BP1.
#   WASM_NF1_MAX_BYTES, WASM_NF1_MAX_GZIP_BYTES: the budgets (Makefile).
#   WASM_OUT: a directory to keep nf1.wasm in (default: none kept).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/client"
pkg=./nf1/internal/jsclient

want="$(awk '$1 == "toolchain" {print $2}' "$root/go.work")"
have="$(go env GOVERSION)"
[[ "$have" == "$want" ]] || { echo "wasm-nf1: toolchain $have, go.work pins $want" >&2; exit 1; }

export GOOS=js GOARCH=wasm CGO_ENABLED=0
banned="$(go list -deps "$pkg" | grep -E '^(google\.golang\.org/grpc|github\.com/nfltr/quic-go|github\.com/nfltr/link|github\.com/nfltr/relay/proto/(pb|wire/dataplane))(/|$)' || true)"
[[ -z "$banned" ]] || { echo "wasm-nf1: the js/wasm build links the relay dial:" >&2; echo "$banned" >&2; exit 1; }

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
build() { go build -trimpath -buildvcs=false -ldflags='-s -w' "$@" "$pkg"; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }
build -o "$out/nf1.wasm"
build -a -o "$out/again.wasm"
sum="$(sha "$out/nf1.wasm")"
[[ "$(sha "$out/again.wasm")" == "$sum" ]] || { echo "wasm-nf1: two builds differ" >&2; exit 1; }

raw="$(wc -c <"$out/nf1.wasm" | tr -d ' ')"
gz="$(gzip -9 -n -c "$out/nf1.wasm" | wc -c | tr -d ' ')"
echo "wasm-nf1: $have sha256 $sum raw $raw (budget $WASM_NF1_MAX_BYTES) gzip $gz (budget $WASM_NF1_MAX_GZIP_BYTES)"
rc=0
((raw <= WASM_NF1_MAX_BYTES)) || { echo "wasm-nf1: raw $raw over budget $WASM_NF1_MAX_BYTES" >&2; rc=1; }
((gz <= WASM_NF1_MAX_GZIP_BYTES)) || { echo "wasm-nf1: gzip $gz over budget $WASM_NF1_MAX_GZIP_BYTES" >&2; rc=1; }

ran="$(GOOS= GOARCH= node "$(go env GOROOT)/lib/wasm/wasm_exec_node.js" "$out/nf1.wasm")" || { echo "wasm-nf1: the session failed under node" >&2; exit 1; }
[[ "$ran" == ok ]] || { echo "wasm-nf1: under node: $ran" >&2; exit 1; }
if [[ -n "${WASM_OUT:-}" ]]; then mkdir -p "$WASM_OUT" && cp "$out/nf1.wasm" "$WASM_OUT/"; fi
exit "$rc"
