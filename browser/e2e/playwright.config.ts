// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "@playwright/test";

// make browser-e2e: the unpacked extension (browser/dist) in Chromium against
// the harness (e2e/harness). One worker: the tests share the harness's relay,
// and one restarts it.
export default defineConfig({
  testDir: ".",
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 20_000 },
  reporter: [["list"]],
  outputDir: "../test-results",
});
