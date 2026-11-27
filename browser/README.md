# nf1 browser extension

Opens an `nf1` address in the browser, end to end: the relay carries the
session and can't read it (nfltr `docs/decisions/browser-peer-2026-11-16.md`).
Manifest V3, for Chrome and Firefox. The handshake is `client/nf1`, the
CLI's own code, compiled to WebAssembly (`client/nf1/internal/extension`).

- `src/nf1.ts`: `NF1Client` and `NF1Socket` (paths, retries, the direct
  path's control session); `src/open.ts`: the page `open.html`, which takes
  the address from its fragment (`open.html#nf1...`) and clears it.
- `make browser-bundle`: builds `dist/` reproducibly (twice, equal
  `SHA256SUMS`, the extension's code pin); `BROWSER_SUMS=<a release's
  SHA256SUMS>` also checks the build is that release's.
- `make browser-e2e`: Playwright drives the unpacked extension in Chromium
  against `e2e/harness` (a relay core and agents on loopback).

Load it unpacked: `chrome://extensions` (developer mode, "Load unpacked",
`dist/`), or `about:debugging` in Firefox ("Load Temporary Add-on",
`dist/manifest.json`).
