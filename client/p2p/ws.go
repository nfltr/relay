// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

// Minimal RFC 6455 WebSocket server-side implementation for the local
// call server, used by a standalone localhost server.

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const (
	wsGUID            = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsOpText     byte = 0x1
	wsOpBinary   byte = 0x2
	wsOpClose    byte = 0x8
	wsOpPing     byte = 0x9
	wsOpPong     byte = 0xA
	wsMaxPayload      = 1 << 20 // 1 MiB
)

// wsConn is a WebSocket connection built on a hijacked net.Conn.
// ReadMessage is not goroutine-safe; WriteMessage is goroutine-safe.
type wsConn struct {
	conn    net.Conn
	rw      *bufio.ReadWriter
	writeMu sync.Mutex
}

// upgradeWS performs the RFC 6455 opening handshake and returns a *wsConn.
func upgradeWS(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, errors.New("not a WebSocket upgrade request")
	}
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key header")
	}
	if r.Header.Get("Sec-Websocket-Version") != "13" {
		return nil, errors.New("unsupported WebSocket version (need 13)")
	}

	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("server does not support connection hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack failed: %w", err)
	}

	_, writeErr := fmt.Fprintf(rw,
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"\r\n",
		accept,
	)
	if writeErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write upgrade response: %w", writeErr)
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("flush upgrade response: %w", err)
	}

	return &wsConn{conn: conn, rw: rw}, nil
}

// ReadMessage reads one complete WebSocket message (assembling continuations).
func (c *wsConn) ReadMessage() (opcode byte, payload []byte, err error) {
	for {
		fin, op, frame, readErr := c.readFrame()
		if readErr != nil {
			return 0, nil, readErr
		}
		if op == wsOpPing {
			_ = c.WriteMessage(wsOpPong, frame)
			continue
		}
		if op == wsOpClose {
			return wsOpClose, frame, io.EOF
		}
		if op != 0x0 { // not continuation
			opcode = op
		}
		payload = append(payload, frame...)
		if fin {
			return opcode, payload, nil
		}
	}
}

func (c *wsConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	header := make([]byte, 2)
	if _, err = io.ReadFull(c.rw, header); err != nil {
		return fin, opcode, payload, err
	}

	fin = header[0]&0x80 != 0
	opcode = header[0] & 0x0F
	masked := header[1]&0x80 != 0
	length := int64(header[1] & 0x7F)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(c.rw, ext); err != nil {
			return fin, opcode, payload, err
		}
		length = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(c.rw, ext); err != nil {
			return fin, opcode, payload, err
		}
		length = int64(ext[0])<<56 | int64(ext[1])<<48 | int64(ext[2])<<40 | int64(ext[3])<<32 |
			int64(ext[4])<<24 | int64(ext[5])<<16 | int64(ext[6])<<8 | int64(ext[7])
	}

	if length > wsMaxPayload {
		err = fmt.Errorf("websocket frame too large (%d bytes, max %d)", length, wsMaxPayload)
		return fin, opcode, payload, err
	}

	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(c.rw, maskKey[:]); err != nil {
			return fin, opcode, payload, err
		}
	}

	payload = make([]byte, length)
	if _, err = io.ReadFull(c.rw, payload); err != nil {
		return fin, opcode, payload, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return fin, opcode, payload, err
}

// WriteMessage sends a single (non-fragmented) WebSocket frame.
// Safe for concurrent use from multiple goroutines.
func (c *wsConn) WriteMessage(opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var header [10]byte
	header[0] = 0x80 | opcode
	n := len(payload)
	hLen := 2
	switch {
	case n < 126:
		header[1] = byte(n)
	case n < 65536:
		header[1] = 126
		header[2] = byte(n >> 8)
		header[3] = byte(n)
		hLen = 4
	default:
		header[1] = 127
		header[2] = 0
		header[3] = 0
		header[4] = 0
		header[5] = 0
		header[6] = byte(n >> 24)
		header[7] = byte(n >> 16)
		header[8] = byte(n >> 8)
		header[9] = byte(n)
		hLen = 10
	}

	if _, err := c.rw.Write(header[:hLen]); err != nil {
		return err
	}
	if _, err := c.rw.Write(payload); err != nil {
		return err
	}
	return c.rw.Flush()
}

// Close sends a normal-closure close frame and closes the underlying conn.
func (c *wsConn) Close() error {
	_ = c.WriteMessage(wsOpClose, []byte{0x03, 0xE8})
	return c.conn.Close()
}
