// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package wsframe reads and writes RFC 6455 WebSocket frames: the one
// framing implementation of the relay's server side (relay ws.go) and the
// CLI's client side (cliutil wsclient.go), both of which carry TCP tunnels.
// It masks eight bytes at a time and reads headers without allocating.
package wsframe

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf8"
)

// Header is one frame's header.
type Header struct {
	Fin    bool
	RSV    byte // the three reserved bits, 0 unless an extension defines them
	Op     byte
	Masked bool
	Key    [4]byte
	Len    int64
}

// ReadHeader reads a frame header from r without allocating.
func ReadHeader(r *bufio.Reader) (Header, error) {
	var h Header
	b, err := next(r, 2)
	if err != nil {
		return h, err
	}
	h.Fin = b[0]&0x80 != 0
	h.RSV = b[0] >> 4 & 7
	h.Op = b[0] & 0x0F
	h.Masked = b[1]&0x80 != 0
	h.Len = int64(b[1] & 0x7F)
	switch h.Len {
	case 126:
		if b, err = next(r, 2); err != nil {
			return h, err
		}
		h.Len = int64(binary.BigEndian.Uint16(b))
	case 127:
		if b, err = next(r, 8); err != nil {
			return h, err
		}
		h.Len = int64(binary.BigEndian.Uint64(b) & (1<<63 - 1))
	}
	if h.Masked {
		if b, err = next(r, 4); err != nil {
			return h, err
		}
		copy(h.Key[:], b)
	}
	return h, nil
}

// next returns the next n bytes of r, valid until r's next read.
func next(r *bufio.Reader, n int) ([]byte, error) {
	b, err := r.Peek(n)
	if err != nil {
		if err == io.EOF && len(b) > 0 {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	_, _ = r.Discard(n)
	return b, nil
}

// ReadFrame reads one frame, unmasking its payload into a new slice the
// caller owns. A payload over max bytes is an error.
func ReadFrame(r *bufio.Reader, max int64) (Header, []byte, error) {
	h, err := ReadHeader(r)
	if err != nil {
		return h, nil, err
	}
	if h.Len > max {
		return h, nil, fmt.Errorf("websocket frame too large (%d bytes, max %d)", h.Len, max)
	}
	p := make([]byte, h.Len)
	if _, err := io.ReadFull(r, p); err != nil {
		return h, nil, err
	}
	if h.Masked {
		Mask(p, h.Key)
	}
	return h, p, nil
}

// AppendHeader appends the header of a final (FIN) frame of opcode op with
// an n-byte payload to dst, masked with key when key is non-nil.
func AppendHeader(dst []byte, op byte, n int, key *[4]byte) []byte {
	var m byte
	if key != nil {
		m = 0x80
	}
	switch {
	case n < 126:
		dst = append(dst, 0x80|op, m|byte(n))
	case n < 1<<16:
		dst = append(dst, 0x80|op, m|126)
		dst = binary.BigEndian.AppendUint16(dst, uint16(n))
	default:
		dst = append(dst, 0x80|op, m|127)
		dst = binary.BigEndian.AppendUint64(dst, uint64(n))
	}
	if key != nil {
		dst = append(dst, key[:]...)
	}
	return dst
}

// AppendFrame appends a final frame of opcode op carrying payload to dst,
// masked with key when key is non-nil (client to server).
func AppendFrame(dst []byte, op byte, payload []byte, key *[4]byte) []byte {
	dst = AppendHeader(dst, op, len(payload), key)
	start := len(dst)
	dst = append(dst, payload...)
	if key != nil {
		Mask(dst[start:], *key)
	}
	return dst
}

// Mask XORs b in place with the repeating 4-byte key, from key offset 0.
func Mask(b []byte, key [4]byte) {
	k := uint64(binary.LittleEndian.Uint32(key[:]))
	k |= k << 32
	for len(b) >= 8 {
		binary.LittleEndian.PutUint64(b, binary.LittleEndian.Uint64(b)^k)
		b = b[8:]
	}
	for i := range b {
		b[i] ^= key[i&3]
	}
}

// Close status codes (RFC 6455 §7.4.1) a reader fails a connection with.
const (
	CloseNormal         uint16 = 1000
	CloseProtocolError  uint16 = 1002
	CloseInvalidPayload uint16 = 1007
	CloseTooBig         uint16 = 1009
)

// CloseError is a peer's protocol violation: the connection must be failed
// with a close frame carrying Code (RFC 6455 §7.1.7).
type CloseError struct {
	Code   uint16
	Reason string
}

// Error implements error. allow:wrapper
func (e *CloseError) Error() string {
	return fmt.Sprintf("websocket protocol error %d: %s", e.Code, e.Reason)
}

// MessageReader assembles messages from frames and enforces RFC 6455's
// framing rules. A control frame (close, ping, pong) is returned as soon as
// it arrives, also between the fragments of a data message, whose assembly
// it leaves intact. Its zero value is ready; one per connection.
type MessageReader struct {
	op  byte   // opcode of the fragmented message being assembled, 0 if none
	buf []byte // its fragments so far
}

// ReadMessage reads frames from r until it has a whole data message (at most
// max bytes, also when fragmented) or a control frame. A violation is a
// *CloseError; other errors are r's.
func (m *MessageReader) ReadMessage(r *bufio.Reader, max int64) (byte, []byte, error) {
	for {
		h, p, err := ReadFrame(r, max)
		if err != nil {
			if h.Len > max {
				return 0, nil, &CloseError{CloseTooBig, err.Error()}
			}
			return 0, nil, err
		}
		if h.RSV != 0 {
			return 0, nil, protocolError("reserved bits set")
		}
		switch {
		case h.Op >= 0x8: // control
			if h.Op > 0xA {
				return 0, nil, protocolError(fmt.Sprintf("reserved opcode %#x", h.Op))
			}
			if !h.Fin || h.Len > 125 {
				return 0, nil, protocolError("fragmented or oversized control frame")
			}
			if h.Op == 0x8 {
				if err := checkClose(p); err != nil {
					return 0, nil, err
				}
			}
			return h.Op, p, nil
		case h.Op > 0x2:
			return 0, nil, protocolError(fmt.Sprintf("reserved opcode %#x", h.Op))
		case h.Op == 0x0:
			if m.op == 0 {
				return 0, nil, protocolError("continuation frame without a message")
			}
			if int64(len(m.buf))+h.Len > max {
				return 0, nil, &CloseError{CloseTooBig, fmt.Sprintf("message over %d bytes", max)}
			}
			m.buf = append(m.buf, p...)
		default: // the first frame of a data message
			if m.op != 0 {
				return 0, nil, protocolError("data frame inside a fragmented message")
			}
			m.op, m.buf = h.Op, p // one frame: no reassembly copy
		}
		if h.Fin {
			op, msg := m.op, m.buf
			m.op, m.buf = 0, nil
			if op == 0x1 && !utf8.Valid(msg) {
				return 0, nil, &CloseError{CloseInvalidPayload, "invalid UTF-8 in a text message"}
			}
			return op, msg, nil
		}
	}
}

func protocolError(reason string) error { return &CloseError{CloseProtocolError, reason} }

// checkClose validates a close frame's payload: empty, or a status code a
// peer may send (RFC 6455 §7.4, plus the IANA-registered 1012-1014) and a
// UTF-8 reason.
func checkClose(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if len(p) == 1 {
		return protocolError("close frame with a 1-byte payload")
	}
	code := binary.BigEndian.Uint16(p)
	if !(code >= 1000 && code <= 1003 || code >= 1007 && code <= 1014 || code >= 3000 && code <= 4999) {
		return protocolError(fmt.Sprintf("close status code %d", code))
	}
	if !utf8.Valid(p[2:]) {
		return &CloseError{CloseInvalidPayload, "invalid UTF-8 in a close reason"}
	}
	return nil
}

// ClosePayload is a close frame's payload carrying status code.
// allow:wrapper: names the wire layout both sides write.
func ClosePayload(code uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, code)
}
