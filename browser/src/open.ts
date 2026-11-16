// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// open.html: one address, one stream at a time, as text lines (nfltr
// docs/decisions/browser-peer-2026-11-16.md section 1). The address comes
// from the page's fragment (never sent to a server: RFC 3986 3.5) or the
// form; the page reads it once and clears it from the URL and the history
// entry. Nothing is stored. The status line carries the session's state
// and, on a failure, its class (data-error), the CLI's exit (data-exit) and
// the relay's close code (data-code).

import { NF1Client, NF1Error, NF1Socket } from "./nf1";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const statusEl = $("status");
const out = $("out");
const relayOnly = $<HTMLInputElement>("relay-only");

function status(state: string, text: string, err?: NF1Error): void {
  statusEl.dataset.state = state;
  for (const k of ["error", "exit", "code"]) delete statusEl.dataset[k];
  if (err) {
    statusEl.dataset.error = err.kind;
    statusEl.dataset.exit = String(err.exit);
    if (err.code !== undefined) statusEl.dataset.code = String(err.code);
    text += `: ${err.kind}${err.exit ? ` (exit ${err.exit})` : ""}${err.code ? `, close ${err.code}` : ""}. ${err.message}`;
  }
  statusEl.textContent = text;
}

let client: NF1Client | undefined;
let sock: NF1Socket | undefined;
const dec = new TextDecoder();

async function start(address: string): Promise<void> {
  client?.close();
  sock?.close();
  out.textContent = "";
  try {
    client = await NF1Client.create(address, { relayOnly: relayOnly.checked, log: (l) => console.log("nf1:", l) });
  } catch (e) {
    status("failed", "Not an address", e as NF1Error);
    return;
  }
  await stream(false);
}

// stream opens a stream and reads it to its end. A stream lost to the
// relay (unreachable: a restart, 1006) is not re-sent: a new stream opens,
// and what the page sent on the old one stays sent once at most.
async function stream(reopening: boolean): Promise<void> {
  const c = client;
  if (!c) return;
  status(reopening ? "reopening" : "opening", reopening ? "Reopening after the relay went" : "Opening");
  let s: NF1Socket;
  try {
    s = await c.open(reopening);
  } catch (e) {
    status("failed", "Not opened", e as NF1Error);
    return;
  }
  if (c !== client) return s.close();
  sock = s;
  $("path").textContent = s.path;
  status("open", `Open on the ${s.path} path`);
  try {
    for (;;) {
      const b = await s.receive();
      if (!b) {
        status("closed", "The service ended the stream");
        return;
      }
      out.textContent += dec.decode(b, { stream: true });
    }
  } catch (e) {
    const err = e as NF1Error;
    if (sock !== s) return; // replaced by a new stream
    if (err.kind === "unreachable" && s.path === "relay") return stream(true);
    status("ended", "The stream ended", err);
  }
}

$("addr-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  void start($<HTMLInputElement>("addr").value);
});
$("send-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const input = $<HTMLInputElement>("send");
  const line = input.value + "\n";
  input.value = "";
  sock?.send(new TextEncoder().encode(line)).catch((e) => status("ended", "Not sent", e as NF1Error));
});
$("half").addEventListener("click", () => void sock?.halfClose());
$("again").addEventListener("click", () => {
  const old = sock;
  sock = undefined;
  old?.close();
  void stream(false);
});

// The fragment: read once, then cleared.
const params = new URLSearchParams(location.search);
relayOnly.checked = params.get("relay") === "only";
const fragment = decodeURIComponent(location.hash.slice(1));
if (fragment) {
  history.replaceState(null, "", location.pathname + location.search);
  void start(fragment);
}
