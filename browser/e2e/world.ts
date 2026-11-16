// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// The e2e world: the harness (e2e/harness: a relay core with nf1 over
// WebSocket, two agents, the TLS front relay.test) and Chromium with the
// unpacked extension, relay.test mapped to the front.

import { test as base, chromium, type BrowserContext, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import path from "node:path";

export interface World {
  front: string;
  ctrl: string;
  spki: string;
  child: ChildProcess;
}

const dist = path.resolve(__dirname, "../dist");
const harness = path.resolve(__dirname, ".harness/harness");

async function startHarness(): Promise<World> {
  const child = spawn(harness, [], { stdio: ["pipe", "pipe", "inherit"] });
  const line = await new Promise<string>((resolve, reject) => {
    child.once("exit", (code) => reject(new Error(`harness exited ${code}`)));
    createInterface({ input: child.stdout! }).once("line", resolve);
  });
  return { ...(JSON.parse(line) as Omit<World, "child">), child };
}

export const test = base.extend<{ page: Page }, { world: World; ctx: BrowserContext; ext: string }>({
  world: [
    async ({}, use) => {
      const w = await startHarness();
      await use(w);
      w.child.stdin!.end();
      await new Promise((r) => w.child.once("exit", r));
    },
    { scope: "worker" },
  ],
  ctx: [
    async ({ world }, use) => {
      const ctx = await chromium.launchPersistentContext("", {
        channel: "chromium",
        headless: true,
        args: [
          `--disable-extensions-except=${dist}`,
          `--load-extension=${dist}`,
          `--host-resolver-rules=MAP relay.test ${world.front}`,
          `--ignore-certificate-errors-spki-list=${world.spki}`,
          "--disable-features=WebRtcHideLocalIpsWithMdns",
        ],
      });
      await use(ctx);
      await ctx.close();
    },
    { scope: "worker" },
  ],
  ext: [
    async ({ ctx }, use) => {
      const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent("serviceworker"));
      await use(new URL(sw.url()).host);
    },
    { scope: "worker" },
  ],
  page: async ({ ctx }, use) => {
    const p = await ctx.newPage();
    p.on("console", (m) => console.log(`page: ${m.text()}`));
    await use(p);
    await p.close();
  },
});

async function ctrl(w: World, method: string, p: string): Promise<string> {
  const res = await fetch(`http://${w.ctrl}${p}`, { method });
  const body = await res.text();
  if (!res.ok) throw new Error(`${method} ${p}: ${res.status} ${body}`);
  return body;
}

export const state = async (w: World) => JSON.parse(await ctrl(w, "GET", "/state")) as { echo: string; direct: string; unknown: string };
export const fault = (w: World, code: number, n: number) => ctrl(w, "POST", `/fault?code=${code}&n=${n}`);
export const count = async (w: World) => Number(await ctrl(w, "GET", "/count"));
export const restart = (w: World) => ctrl(w, "POST", "/restart");
