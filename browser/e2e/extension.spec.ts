// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// The extension against a relay core and agents (nfltr
// docs/decisions/browser-peer-2026-11-16.md, lane BP4): the fragment read
// once and cleared, session bytes end to end, each close code of the relay
// path mapped to the CLI's class and exit, retries only where no byte was
// sent, a relay restart mid-session reopened without re-sending, the direct
// path and "relay only".

import { expect, type Page } from "@playwright/test";
import { count, fault, restart, state, test, type World } from "./world";

const open = (page: Page, ext: string, address: string, query = "") =>
  page.goto(`chrome-extension://${ext}/open.html${query}#${encodeURIComponent(address)}`);
const statusEl = (page: Page) => page.locator("#status");

async function send(page: Page, line: string) {
  await page.locator("#send").fill(line);
  await page.locator("#send").press("Enter");
}

test("an address in the fragment is read once and cleared; the session's bytes come back", async ({ page, ext, world }) => {
  const { echo } = await state(world);
  await count(world);
  await open(page, ext, echo);
  await expect(statusEl(page)).toHaveAttribute("data-state", "open");
  expect(page.url()).not.toContain("#");
  expect(page.url()).not.toContain(echo);
  await expect(page.locator("#path")).toHaveText("relay");
  await send(page, "hello over nf1");
  await expect(page.locator("#out")).toHaveText("hello over nf1\n");
  expect(await count(world)).toBe(1);
});

test("an unknown address: not served (close 4003, exit 3), not retried", async ({ page, ext, world }) => {
  const { unknown } = await state(world);
  await count(world);
  await open(page, ext, unknown);
  await expect(statusEl(page)).toHaveAttribute("data-error", "not_served");
  await expect(statusEl(page)).toHaveAttribute("data-exit", "3");
  await expect(statusEl(page)).toHaveAttribute("data-code", "4003");
  expect(await count(world)).toBe(1);
});

test("not an address: refused before any connection", async ({ page, ext, world }) => {
  await count(world);
  await open(page, ext, "nf1notanaddress");
  await expect(statusEl(page)).toHaveAttribute("data-error", "address");
  expect(await count(world)).toBe(0);
});

// Each refusal the relay gives at the open: its class and exit, and one
// attempt only (a refusal is an answer, not an outage).
for (const [code, kind, exit] of [
  [4004, "refused", 4],
  [4009, "balance", 9],
  [1011, "reset", 0],
  [1001, "idle", 0],
  [1003, "protocol", 0],
  [1000, "closed", 0],
] as const) {
  test(`close ${code} at the open: ${kind}, exit ${exit}, not retried`, async ({ page, ext, world }) => {
    const { echo } = await state(world);
    await count(world);
    await fault(world, code, 1);
    await open(page, ext, echo);
    await expect(statusEl(page)).toHaveAttribute("data-error", kind);
    await expect(statusEl(page)).toHaveAttribute("data-exit", String(exit));
    await expect(statusEl(page)).toHaveAttribute("data-code", String(code));
    expect(await count(world)).toBe(1);
    await fault(world, 0, 0);
  });
}

// An unreachable relay path (1013 no route now, 1006 dropped) is retried:
// no byte of the stream was sent. Past the retries: unreachable, exit 5.
for (const code of [1013, 1006]) {
  test(`close ${code} at the open: retried, then unreachable (exit 5)`, async ({ page, ext, world }) => {
    const { echo } = await state(world);
    await count(world);
    await fault(world, code, 100);
    await open(page, ext, echo);
    await expect(statusEl(page)).toHaveAttribute("data-error", "unreachable");
    await expect(statusEl(page)).toHaveAttribute("data-exit", "5");
    await expect(statusEl(page)).toHaveAttribute("data-code", String(code));
    expect(await count(world)).toBe(5); // the open and its 4 retries
    await fault(world, 0, 0);
  });
}

test("a relay path unreachable twice opens on the third attempt", async ({ page, ext, world }) => {
  const { echo } = await state(world);
  await count(world);
  await fault(world, 1013, 2);
  await open(page, ext, echo);
  await expect(statusEl(page)).toHaveAttribute("data-state", "open");
  expect(await count(world)).toBe(3);
  await send(page, "third time");
  await expect(page.locator("#out")).toHaveText("third time\n");
});

test("a relay restart mid-session: the stream fails, the page reopens, nothing is sent twice", async ({ page, ext, world }) => {
  const { echo } = await state(world);
  await open(page, ext, echo);
  await expect(statusEl(page)).toHaveAttribute("data-state", "open");
  await send(page, "before");
  await expect(page.locator("#out")).toHaveText("before\n");
  const states: string[] = [];
  page.on("console", (m) => states.push(m.text()));
  await page.exposeFunction("seen", (s: string) => states.push(s));
  await page.evaluate(() => {
    const el = document.getElementById("status")!;
    new MutationObserver(() => (window as unknown as { seen(s: string): void }).seen(el.dataset.state ?? "")).observe(el, { attributes: true });
  });
  await restart(world);
  await expect.poll(() => states.includes("reopening")).toBe(true);
  await expect(statusEl(page)).toHaveAttribute("data-state", "open", { timeout: 60_000 });
  await send(page, "after");
  await expect(page.locator("#out")).toHaveText("before\nafter\n");
});

test("the direct path: streams after the first take a data channel; relay only never does", async ({ page, ext, world }) => {
  const { direct } = await state(world);
  await open(page, ext, direct);
  await expect(statusEl(page)).toHaveAttribute("data-state", "open");
  await expect(page.locator("#path")).toHaveText("relay");
  await expect
    .poll(
      async () => {
        await page.locator("#again").click();
        await expect(statusEl(page)).toHaveAttribute("data-state", "open");
        return page.locator("#path").textContent();
      },
      { timeout: 30_000 },
    )
    .toBe("direct");
  await send(page, "over a data channel");
  await expect(page.locator("#out")).toContainText("over a data channel\n");

  await open(page, ext, direct, "?relay=only");
  await expect(statusEl(page)).toHaveAttribute("data-state", "open");
  for (let i = 0; i < 3; i++) {
    await page.locator("#again").click();
    await expect(statusEl(page)).toHaveAttribute("data-state", "open");
    await expect(page.locator("#path")).toHaveText("relay");
  }
});

export type { World };
