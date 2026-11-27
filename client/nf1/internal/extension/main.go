// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

// Command extension is the nf1 client of the browser extension (nfltr
// docs/decisions/browser-peer-2026-11-16.md, lane BP4; relay browser/):
// client/nf1's handshake, the CLI's own code, on a transport the page
// made (a WebSocket to wss://R/nf1/v1, or an RTCDataChannel of the direct
// path), exported to the page's script as globalThis.nf1go. Each call that
// waits returns a Promise; a refusal rejects with {name, exit, code,
// reason, message}: the class and exit the CLI gives the same answer
// (jsconn.Classify), the WebSocket's close code and reason. The page owns
// the policy (paths, retries, reopening); this owns the bytes.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"syscall/js"
	"time"

	"github.com/nfltr/relay/client/capaddr"
	"github.com/nfltr/relay/client/nf1"
	"github.com/nfltr/relay/client/nf1/internal/jsconn"
)

// controlMark is the page's first byte after the answer on a control
// session (client/agent direct_nf1.go).
const controlMark = 'B'

// maxSignal bounds one SDP message (client/p2p BrowserMaxSignal).
const maxSignal = 16 << 10

type session struct {
	raw *jsconn.Conn
	tc  *tls.Conn
}

var (
	mu       sync.Mutex
	sessions = map[int]*session{}
	nextID   int
)

func main() {
	js.Global().Set("nf1go", js.ValueOf(map[string]any{
		"parse":      js.FuncOf(parse),
		"open":       js.FuncOf(open),
		"read":       js.FuncOf(read),
		"write":      js.FuncOf(write),
		"closeWrite": js.FuncOf(closeWrite),
		"close":      js.FuncOf(closeSession),
		"sendSignal": js.FuncOf(sendSignal),
		"readSignal": js.FuncOf(readSignal),
	}))
	select {}
}

// jsError is a rejection's value: the class, the CLI's exit, the close.
func jsError(err error, closed *jsconn.CloseError) js.Value {
	name, exit := jsconn.Classify(err, closed)
	e := js.Global().Get("Error").New(err.Error())
	if closed != nil {
		e.Set("code", closed.Code)
		e.Set("reason", closed.Reason)
		e.Set("message", closed.Error())
	}
	e.Set("name", name)
	e.Set("exit", exit)
	return e
}

// promise runs f off the event loop and settles a Promise with its value.
func promise(f func() (any, error, *jsconn.CloseError)) any {
	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, a []js.Value) any {
		resolve, reject := a[0], a[1]
		go func() {
			defer executor.Release()
			v, err, closed := f()
			if err != nil {
				reject.Invoke(jsError(err, closed))
				return
			}
			resolve.Invoke(v)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(executor)
}

func lookup(id js.Value) (*session, error) {
	mu.Lock()
	defer mu.Unlock()
	if s := sessions[id.Int()]; s != nil {
		return s, nil
	}
	return nil, errors.New("nf1: no such session")
}

// parse(address) -> {relay} or {error}: the address's relay host (a panic
// here would end the Go program, so an error is a value).
func parse(_ js.Value, a []js.Value) any {
	addr, err := capaddr.Parse(a[0].String())
	if err != nil {
		return js.ValueOf(map[string]any{"error": err.Error()})
	}
	return js.ValueOf(map[string]any{"relay": addr.Relay})
}

// open(transport, address, {relayed, control, max}) -> Promise<{id, hints}>:
// the nf1 session on transport (a WebSocket or RTCDataChannel, open or
// not). relayed: write the rid first (the relay path). control: a control
// session (the direct path's SDP exchange): refused unless the answer says
// the agent takes browsers. max: the transport's largest message.
func open(_ js.Value, a []js.Value) any {
	t, text, opts := a[0], a[1].String(), a[2]
	raw := jsconn.New(t, opts.Get("max").Int())
	return promise(func() (any, error, *jsconn.CloseError) {
		s, hints, err := handshake(raw, text, opts.Get("relayed").Truthy(), opts.Get("control").Truthy())
		if err != nil {
			closed := raw.Closed()
			_ = raw.Close()
			return nil, err, closed
		}
		mu.Lock()
		nextID++
		id := nextID
		sessions[id] = s
		mu.Unlock()
		return js.ValueOf(map[string]any{"id": id, "hints": string(hints)}), nil, nil
	})
}

func handshake(raw *jsconn.Conn, text string, relayed, control bool) (*session, []byte, error) {
	addr, err := capaddr.Parse(text)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), nf1.HandshakeTimeout)
	defer cancel()
	_ = raw.SetDeadline(time.Now().Add(nf1.HandshakeTimeout))
	if relayed {
		if _, err := raw.Write(addr.RID[:]); err != nil {
			return nil, nil, err
		}
	}
	hints, err := nf1.ReadAnswer(raw, addr)
	if err != nil {
		return nil, nil, err
	}
	if err := nf1.CheckKind(hints, false); err != nil {
		return nil, nil, err
	}
	if control {
		if !nf1.TakesBrowser(hints) {
			return nil, nil, errors.New("nf1: the agent takes no browser direct path")
		}
		if _, err := raw.Write([]byte{controlMark}); err != nil {
			return nil, nil, err
		}
	}
	tc, err := nf1.ClientTLS(ctx, raw, addr)
	if err != nil {
		return nil, nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return &session{raw: raw, tc: tc}, hints, nil
}

// read(id) -> Promise<Uint8Array|null>: the session's next bytes, null at
// its clean end (close_notify or close 1000).
func read(_ js.Value, a []js.Value) any {
	id := a[0]
	return promise(func() (any, error, *jsconn.CloseError) {
		s, err := lookup(id)
		if err != nil {
			return nil, err, nil
		}
		buf := make([]byte, 64<<10)
		n, err := s.tc.Read(buf)
		if n > 0 {
			b := js.Global().Get("Uint8Array").New(n)
			js.CopyBytesToJS(b, buf[:n])
			return b, nil, nil
		}
		if errors.Is(err, io.EOF) {
			return js.Null(), nil, nil
		}
		return nil, err, s.raw.Closed()
	})
}

// write(id, Uint8Array) -> Promise<void>.
func write(_ js.Value, a []js.Value) any {
	id, b := a[0], make([]byte, a[1].Get("byteLength").Int())
	js.CopyBytesToGo(b, a[1])
	return promise(func() (any, error, *jsconn.CloseError) {
		s, err := lookup(id)
		if err != nil {
			return nil, err, nil
		}
		if _, err := s.tc.Write(b); err != nil {
			return nil, err, s.raw.Closed()
		}
		return js.Undefined(), nil, nil
	})
}

// closeWrite(id) -> Promise<void>: the session's half close (TLS
// close_notify; a WebSocket or channel has none of its own).
func closeWrite(_ js.Value, a []js.Value) any {
	id := a[0]
	return promise(func() (any, error, *jsconn.CloseError) {
		s, err := lookup(id)
		if err != nil {
			return nil, err, nil
		}
		if err := s.tc.CloseWrite(); err != nil {
			return nil, err, s.raw.Closed()
		}
		return js.Undefined(), nil, nil
	})
}

// close(id): ends the session and its transport.
func closeSession(_ js.Value, a []js.Value) any {
	mu.Lock()
	s := sessions[a[0].Int()]
	delete(sessions, a[0].Int())
	mu.Unlock()
	if s != nil {
		_ = s.raw.Close()
	}
	return nil
}

// sendSignal(id, json) -> Promise<void>: one message of a control session
// (a u16 big-endian length, then the bytes; "" is the keepalive).
func sendSignal(_ js.Value, a []js.Value) any {
	id, msg := a[0], a[1].String()
	return promise(func() (any, error, *jsconn.CloseError) {
		s, err := lookup(id)
		if err != nil {
			return nil, err, nil
		}
		if len(msg) > maxSignal {
			return nil, errors.New("nf1: signal over 16 KiB"), nil
		}
		b := binary.BigEndian.AppendUint16(nil, uint16(len(msg))) // #nosec G115 -- bounded above
		if _, err := s.tc.Write(append(b, msg...)); err != nil {
			return nil, err, s.raw.Closed()
		}
		return js.Undefined(), nil, nil
	})
}

// readSignal(id) -> Promise<string>: the control session's next message
// ("": the agent has no connection to give now).
func readSignal(_ js.Value, a []js.Value) any {
	id := a[0]
	return promise(func() (any, error, *jsconn.CloseError) {
		s, err := lookup(id)
		if err != nil {
			return nil, err, nil
		}
		var n [2]byte
		if _, err := io.ReadFull(s.tc, n[:]); err != nil {
			return nil, err, s.raw.Closed()
		}
		size := int(binary.BigEndian.Uint16(n[:]))
		if size > maxSignal {
			return nil, errors.New("nf1: signal over 16 KiB"), nil
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(s.tc, b); err != nil {
			return nil, err, s.raw.Closed()
		}
		return string(b), nil, nil
	})
}
