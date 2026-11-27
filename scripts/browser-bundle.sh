#!/usr/bin/env bash
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0
#
# browser-bundle.sh: the nf1 browser extension (browser/; nfltr
# docs/decisions/browser-peer-2026-11-16.md section 3, lane BP4), built
# reproducibly: the wasm client (client/nf1/internal/extension) with the
# toolchain go.work pins, -trimpath, no VCS stamp; the toolchain's
# wasm_exec.js; the page's TypeScript bundled by the esbuild
# browser/package-lock.json pins; the static files. Built twice (the second
# Go build from source, -a) and both SHA256SUMS listings equal; the listing
# (client/internal/bundle, BIND:browser.bundle) is the extension's code
# pin, for the release's signed SHA256SUMS. Fails over the wasm budgets.
# Prints the listing, the sizes and the listing's own sha256.
#   BROWSER_OUT: where the extension is written (default browser/dist).
#   BROWSER_SUMS: a release's SHA256SUMS; the build must equal it (the
#     store package's check: rebuild and compare).
#   WASM_NF1_MAX_BYTES, WASM_NF1_MAX_GZIP_BYTES: nf1.wasm's budgets.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${BROWSER_OUT:-$root/browser/dist}"

want="$(awk '$1 == "toolchain" {print $2}' "$root/go.work")"
have="$(cd "$root/client" && go env GOVERSION)"
[[ "$have" == "$want" ]] || { echo "browser-bundle: toolchain $have, go.work pins $want" >&2; exit 1; }
goroot="$(cd "$root/client" && go env GOROOT)"

(cd "$root/browser" && npm ci --no-audit --no-fund --silent)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
build() { # build DIR [go build flags]
  local dir="$1"
  shift
  mkdir -p "$dir"
  (cd "$root/client" && GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' "$@" -o "$dir/nf1.wasm" ./nf1/internal/extension)
  cp "$goroot/lib/wasm/wasm_exec.js" "$root"/browser/static/* "$dir/"
  (cd "$root/browser" && ./node_modules/.bin/esbuild src/open.ts src/bg.ts --bundle --format=esm --target=es2022 --charset=utf8 --legal-comments=none --log-level=warning --outdir="$dir")
  (cd "$root/client" && go run ./internal/bundle/sums "$dir") >"$dir/SHA256SUMS"
}
build "$tmp/a"
build "$tmp/b" -a
cmp -s "$tmp/a/SHA256SUMS" "$tmp/b/SHA256SUMS" || { echo "browser-bundle: two builds differ" >&2; diff "$tmp/a/SHA256SUMS" "$tmp/b/SHA256SUMS" >&2; exit 1; }
if [[ -n "${BROWSER_SUMS:-}" ]]; then
  (cd "$root/client" && go run ./internal/bundle/sums -check "$BROWSER_SUMS" "$tmp/a") || { echo "browser-bundle: not the release's bundle ($BROWSER_SUMS)" >&2; exit 1; }
fi
rm -rf "$out"
mkdir -p "$(dirname "$out")"
cp -R "$tmp/a" "$out"

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }
cat "$out/SHA256SUMS"
raw="$(wc -c <"$out/nf1.wasm" | tr -d ' ')"
gz="$(gzip -9 -n -c "$out/nf1.wasm" | wc -c | tr -d ' ')"
total="$(cat "$out"/* | wc -c | tr -d ' ')"
echo "browser-bundle: $have SHA256SUMS sha256 $(sha "$out/SHA256SUMS"); nf1.wasm raw $raw (budget $WASM_NF1_MAX_BYTES) gzip $gz (budget $WASM_NF1_MAX_GZIP_BYTES); extension $total bytes in $out"
((raw <= WASM_NF1_MAX_BYTES)) || { echo "browser-bundle: nf1.wasm raw $raw over budget" >&2; exit 1; }
((gz <= WASM_NF1_MAX_GZIP_BYTES)) || { echo "browser-bundle: nf1.wasm gzip $gz over budget" >&2; exit 1; }
