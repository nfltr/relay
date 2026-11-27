// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// The script-free view of an HTTP service (nfltr
// docs/decisions/browser-peer-2026-11-16.md section 1): one request per nf1
// stream; HTML goes into a sandbox iframe (no allow-scripts, no
// allow-same-origin) under CSP default-src 'none', so no script of the
// agent's runs and none reaches the extension's storage or other addresses;
// any other type is offered as a download.
//
// ponytail: HTTP/1.0, one request per stream, no keep-alive pool, no images
// fetched for the page (CSP blocks them); add the pool and blob: images when
// a page needs them.

import type { NF1Client } from "./nf1";

export interface Response {
  status: number;
  type: string;
  body: Uint8Array;
}

const maxBody = 16 << 20;

export async function fetchOver(c: NF1Client, path: string): Promise<Response> {
  if (!path.startsWith("/") || /[\s]/.test(path)) throw new Error("the path is one /-rooted word");
  const s = await c.open();
  try {
    await s.send(new TextEncoder().encode(`GET ${path} HTTP/1.0\r\nHost: nf1\r\nAccept: */*\r\n\r\n`));
    const parts: Uint8Array[] = [];
    let size = 0;
    for (let b = await s.receive(); b; b = await s.receive()) {
      if ((size += b.length) > maxBody) throw new Error("the response is over 16 MiB");
      parts.push(b);
    }
    return parse(concat(parts, size));
  } finally {
    s.close();
  }
}

function concat(parts: Uint8Array[], size: number): Uint8Array {
  const all = new Uint8Array(size);
  let off = 0;
  for (const p of parts) {
    all.set(p, off);
    off += p.length;
  }
  return all;
}

function parse(raw: Uint8Array): Response {
  let end = -1;
  for (let i = 0; i + 3 < raw.length; i++) {
    if (raw[i] === 13 && raw[i + 1] === 10 && raw[i + 2] === 13 && raw[i + 3] === 10) {
      end = i;
      break;
    }
  }
  if (end < 0) throw new Error("no HTTP response head");
  const [line, ...headers] = new TextDecoder().decode(raw.subarray(0, end)).split("\r\n");
  const m = /^HTTP\/1\.[01] (\d{3})/.exec(line);
  if (!m) throw new Error("no HTTP status line");
  const type = headers.find((h) => /^content-type:/i.test(h))?.replace(/^content-type:\s*/i, "") ?? "application/octet-stream";
  return { status: Number(m[1]), type, body: raw.subarray(end + 4) };
}

const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`;

export function render(res: Response, frame: HTMLIFrameElement, status: HTMLElement): void {
  frame.hidden = true;
  if (/^text\/html\b/i.test(res.type)) {
    frame.srcdoc = csp + new TextDecoder().decode(res.body);
    frame.hidden = false;
    return;
  }
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([res.body as BlobPart], { type: "application/octet-stream" }));
  a.download = "nf1-download";
  a.textContent = " Download";
  status.append(a);
}
