// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// The page's side of an nf1 address (nfltr docs/decisions/browser-peer-2026-11-16.md,
// lane BP4): NF1Socket, one stream to the address's service, and NF1Client,
// which picks its path. The handshake is client/nf1, the CLI's own code, in
// nf1.wasm (client/nf1/internal/extension: globalThis.nf1go); this file owns
// the policy: which transport, retries, the direct path's control session.
//
// Paths (section 2): the relay path is a WebSocket to wss://R/nf1/v1
// (subprotocol nf1.v1), R the address's own relay. The direct path, when the
// agent's signed hints say b1 and the visitor did not choose "relay only", is
// a data channel per stream of one RTCPeerConnection whose SDP travels inside
// a control session (an nf1 session over the WebSocket). A stream keeps its
// path: when it fails it fails to the app, never re-sent elsewhere
// (BrowserPeer.tla AtMostOnce).

declare const Go: new () => { importObject: WebAssembly.Imports; run(i: WebAssembly.Instance): Promise<void> };

interface GoSession { id: number; hints: string }
interface NF1Go {
  parse(address: string): { relay?: string; error?: string };
  open(t: WebSocket | RTCDataChannel, address: string, o: { relayed: boolean; control: boolean; max: number }): Promise<GoSession>;
  read(id: number): Promise<Uint8Array | null>;
  write(id: number, b: Uint8Array): Promise<void>;
  closeWrite(id: number): Promise<void>;
  close(id: number): void;
  sendSignal(id: number, msg: string): Promise<void>;
  readSignal(id: number): Promise<string>;
}

// Error classes: the CLI's for the same answer (client/nf1/internal/jsconn
// Classify): not_served (exit 3, close 4003), refused (4, 4004), unreachable
// (5: 1013, 1006, no relay), balance (9, 4009), pin (7), proof (10), reset
// (1011), idle (1001), protocol (1003), timeout, address, kind, answer.
export class NF1Error extends Error {
  constructor(
    readonly kind: string,
    message: string,
    readonly exit = 0,
    readonly code?: number,
    readonly reason?: string,
  ) {
    super(message);
    this.name = "NF1Error";
  }
}

function asNF1Error(e: unknown): NF1Error {
  if (e instanceof NF1Error) return e;
  const x = e as { name?: string; message?: string; exit?: number; code?: number; reason?: string };
  return new NF1Error(x.name ?? "error", x.message ?? String(e), x.exit ?? 0, x.code, x.reason);
}

let loaded: Promise<NF1Go> | undefined;

// load starts nf1.wasm once (wasm_exec.js, the toolchain's, is a script of
// the page).
export function load(url = "nf1.wasm"): Promise<NF1Go> {
  loaded ??= (async () => {
    const go = new Go();
    const { instance } = await WebAssembly.instantiateStreaming(fetch(url), go.importObject);
    void go.run(instance);
    return (globalThis as unknown as { nf1go: NF1Go }).nf1go;
  })();
  return loaded;
}

const wsMax = 1 << 20; // the relay's frame bound
const dcMax = 64 << 10; // the agent's a=max-message-size

// NF1Socket is one stream to the address's service: its bytes inside the
// nf1 session's TLS, on the path it opened on.
export class NF1Socket {
  constructor(
    private readonly go: NF1Go,
    readonly id: number,
    readonly path: "relay" | "direct",
    readonly hints: string,
  ) {}

  send(data: Uint8Array): Promise<void> {
    return this.go.write(this.id, data).catch((e) => Promise.reject(asNF1Error(e)));
  }
  // receive is the next bytes, null at the stream's clean end.
  receive(): Promise<Uint8Array | null> {
    return this.go.read(this.id).catch((e) => Promise.reject(asNF1Error(e)));
  }
  // halfClose ends the page's direction (TLS close_notify).
  halfClose(): Promise<void> {
    return this.go.closeWrite(this.id).catch((e) => Promise.reject(asNF1Error(e)));
  }
  close(): void {
    this.go.close(this.id);
  }
}

export interface ClientOptions {
  // relayOnly: never the direct path (the agent would learn the visitor's IP).
  relayOnly?: boolean;
  // retries of an unreachable relay path's open (1013, 1006, no relay): no
  // byte of the stream was sent, so a retry replays nothing.
  retries?: number;
  // retryDelayMs: the first retry's delay, doubled each time.
  retryDelayMs?: number;
  // log, for the page's status line.
  log?: (line: string) => void;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// relayURL is the address's relay path: its own relay, never another
// (BIND:cap.rendezvous refuses another's answer).
export function relayURL(relay: string): string {
  return `wss://${relay}/nf1/v1`;
}

// NF1Client opens streams to one address.
export class NF1Client {
  private direct?: Direct;

  private constructor(
    private readonly go: NF1Go,
    readonly address: string,
    readonly relay: string,
    private readonly opts: ClientOptions,
  ) {}

  static async create(address: string, opts: ClientOptions = {}): Promise<NF1Client> {
    const go = await load();
    const p = go.parse(address.trim());
    if (p.error || !p.relay) throw new NF1Error("address", p.error ?? "not an nf1 address");
    return new NF1Client(go, address.trim(), p.relay, opts);
  }

  // open is a new stream: on the direct path when its connection is up,
  // else on the relay path, retried while the relay is unreachable.
  // reopening (a session just lost to the relay) also retries not_served for
  // as long: the agent re-registers after a relay restart.
  async open(reopening = false): Promise<NF1Socket> {
    const d = this.direct?.ready ? this.direct : undefined;
    if (d) {
      const s = await d.stream();
      if (s) return s; // else: the channel was refused before any byte (past MaxDC): the WebSocket
    }
    const s = await this.openRelay(false, reopening);
    if (!this.opts.relayOnly && !this.direct && s.hints.split(",").includes("b1")) {
      this.direct = new Direct(this, this.go, this.opts.log);
      void this.direct.start();
    }
    return s;
  }

  // openRelay is one nf1 session over a new WebSocket (a stream, or a
  // control session), with the retries of ClientOptions.
  async openRelay(control: boolean, reopening = false): Promise<NF1Socket> {
    const retries = this.opts.retries ?? 4;
    let delay = this.opts.retryDelayMs ?? 250;
    for (let attempt = 0; ; attempt++) {
      const ws = new WebSocket(relayURL(this.relay), "nf1.v1");
      try {
        const g = await this.go.open(ws, this.address, { relayed: true, control, max: wsMax });
        return new NF1Socket(this.go, g.id, "relay", g.hints);
      } catch (e) {
        const err = asNF1Error(e);
        const again = err.kind === "unreachable" || err.kind === "timeout" || (reopening && err.kind === "not_served");
        if (!again || attempt >= retries) throw err;
        this.opts.log?.(`retry ${attempt + 1}: ${err.kind} ${err.code ?? ""}`);
        await sleep(delay);
        delay *= 2;
      }
    }
  }

  close(): void {
    this.direct?.close();
    this.direct = undefined;
  }
}

// Direct is the direct path: one RTCPeerConnection set up over a control
// session, a data channel per stream (the decision's BP3 wire).
class Direct {
  ready = false;
  private pc?: RTCPeerConnection;
  private ctl?: NF1Socket;
  private keepalive?: ReturnType<typeof setInterval>;
  private first?: Promise<GoSession>;

  constructor(
    private readonly c: NF1Client,
    private readonly go: NF1Go,
    private readonly log?: (line: string) => void,
  ) {}

  // channel starts a stream's nf1 session on a new data channel at once:
  // the agent writes its answer when the channel opens, and a message
  // before the page listens would be lost.
  private channel(pc: RTCPeerConnection): Promise<GoSession> {
    const p = this.go.open(pc.createDataChannel("nf1"), this.c.address, { relayed: false, control: false, max: dcMax });
    p.catch(() => {}); // the first one may never be awaited
    return p;
  }

  async start(): Promise<void> {
    try {
      // The first stream's channel exists before the offer, so the SDP has
      // the application section; it is used by the first stream opened.
      const pc = new RTCPeerConnection({ iceServers: [] });
      this.pc = pc;
      this.first = this.channel(pc);
      await pc.setLocalDescription(await pc.createOffer());
      await gathered(pc);
      const ctl = await this.c.openRelay(true);
      this.ctl = ctl;
      const id = ctl.id;
      await this.go.sendSignal(id, JSON.stringify(pc.localDescription));
      const answer = await this.go.readSignal(id);
      if (answer === "") throw new NF1Error("no_direct", "the agent has no direct connection to give now");
      await pc.setRemoteDescription(JSON.parse(answer) as RTCSessionDescriptionInit);
      this.keepalive = setInterval(() => void this.go.sendSignal(id, "").catch(() => this.close()), 60_000);
      pc.onconnectionstatechange = () => {
        if (pc.connectionState === "connected") this.ready = true;
        if (pc.connectionState === "failed" || pc.connectionState === "closed") this.close();
      };
      // The control session's end ends the connection (the agent reaps it).
      void this.go.readSignal(id).then(
        () => this.close(),
        () => this.close(),
      );
    } catch (e) {
      this.log?.(`direct path: ${asNF1Error(e).kind}`);
      this.close();
    }
  }

  // stream is a stream on a new data channel, or undefined when the agent
  // closed the channel before its answer (past its MaxDC): no byte was sent.
  async stream(): Promise<NF1Socket | undefined> {
    const pc = this.pc;
    if (!pc) return undefined;
    const p = this.first ?? this.channel(pc);
    this.first = undefined;
    try {
      const g = await p;
      return new NF1Socket(this.go, g.id, "direct", g.hints);
    } catch (e) {
      const err = asNF1Error(e);
      if (err.kind === "closed") return undefined;
      throw err; // its own handshake failed: to the app (BrowserPeer.tla Refuse)
    }
  }

  close(): void {
    this.ready = false;
    if (this.keepalive) clearInterval(this.keepalive);
    this.ctl?.close();
    this.pc?.close();
    this.ctl = this.pc = this.first = undefined;
  }
}

// gathered waits for the offer's candidates (no trickle), at most 5 s.
function gathered(pc: RTCPeerConnection): Promise<void> {
  if (pc.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    const t = setTimeout(resolve, 5000);
    pc.onicegatheringstatechange = () => {
      if (pc.iceGatheringState === "complete") {
        clearTimeout(t);
        resolve();
      }
    };
  });
}
