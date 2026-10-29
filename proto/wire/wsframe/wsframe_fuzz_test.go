// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wsframe

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
	"unicode/utf8"
)

const fuzzMax = 1 << 16

// FuzzReadMessage feeds arbitrary bytes, as a peer would, to ReadHeader,
// ReadFrame and MessageReader: no panic, no payload over max, and every
// violation is a CloseError with a code a reader may fail a connection with.
func FuzzReadMessage(f *testing.F) {
	long := bytes.Repeat([]byte{'a'}, 126)
	for _, seed := range [][]byte{
		nil,
		frame(true, 0, 0x2, []byte("hello")),
		frame(true, 0, 0x1, long),
		frame(true, 0, 0x2, make([]byte, 1<<16)),
		frame(true, 1, 0x2, nil),
		frame(true, 0, 0xB, nil),
		frame(false, 0, 0x9, nil),
		frame(true, 0, 0x8, append(ClosePayload(1000), "bye"...)),
		frame(true, 0, 0x8, []byte{3}),
		frame(true, 0, 0x1, []byte{0xce, 0xba, 0xff}),
		slices.Concat(frame(false, 0, 0x2, []byte("frag")), frame(true, 0, 0x9, []byte("ping")),
			frame(false, 0, 0x0, []byte("ment")), frame(true, 0, 0x0, []byte("ed"))),
		AppendFrame(nil, 0x2, []byte("unmasked"), nil),
		{0x82, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // 64-bit length, top bit set
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		r := bufio.NewReader(bytes.NewReader(wire))
		for {
			if _, err := ReadHeader(r); err != nil {
				break
			}
		}

		r = bufio.NewReader(bytes.NewReader(wire))
		for {
			h, p, err := ReadFrame(r, fuzzMax)
			if err != nil {
				if p != nil {
					t.Fatalf("payload of %d bytes returned with error %v", len(p), err)
				}
				break
			}
			if int64(len(p)) != h.Len || h.Len > fuzzMax {
				t.Fatalf("payload %d bytes, header %d, max %d", len(p), h.Len, fuzzMax)
			}
		}

		var m MessageReader
		r = bufio.NewReader(bytes.NewReader(wire))
		for {
			op, p, err := m.ReadMessage(r, fuzzMax)
			if err != nil {
				if ce, ok := errors.AsType[*CloseError](err); ok &&
					ce.Code != CloseProtocolError && ce.Code != CloseInvalidPayload && ce.Code != CloseTooBig {
					t.Fatalf("close code %d: %v", ce.Code, err)
				}
				return
			}
			switch {
			case len(p) > fuzzMax:
				t.Fatalf("message of %d bytes, max %d", len(p), fuzzMax)
			case op >= 0x8 && (op > 0xA || len(p) > 125):
				t.Fatalf("control op %#x with %d bytes", op, len(p))
			case op == 0x0 || op > 0x2 && op < 0x8:
				t.Fatalf("message with opcode %#x", op)
			case op == 0x1 && !utf8.Valid(p):
				t.Fatalf("invalid UTF-8 text message %q", p)
			}
		}
	})
}

// FuzzFrameRoundTrip: AppendFrame's output reads back through ReadFrame as
// the opcode and payload written, masked or not, consuming exactly the frame.
func FuzzFrameRoundTrip(f *testing.F) {
	f.Add(byte(0x2), []byte("hello"), true, uint32(0x01020304))
	f.Add(byte(0x1), bytes.Repeat([]byte{'a'}, 126), false, uint32(0))
	f.Add(byte(0x2), make([]byte, 1<<16), true, uint32(0xdeadbeef))
	f.Add(byte(0x8), ClosePayload(1000), true, uint32(0xffffffff))
	f.Add(byte(0x0), []byte(nil), false, uint32(7))
	f.Fuzz(func(t *testing.T, op byte, payload []byte, masked bool, k uint32) {
		op &= 0x0F
		var key *[4]byte
		if masked {
			key = new([4]byte)
			binary.BigEndian.PutUint32(key[:], k)
		}
		orig := slices.Clone(payload)
		wire := AppendFrame(nil, op, payload, key)
		if !bytes.Equal(payload, orig) {
			t.Fatal("AppendFrame modified its payload")
		}
		r := bufio.NewReader(bytes.NewReader(wire))
		h, p, err := ReadFrame(r, int64(len(payload)))
		if err != nil {
			t.Fatal(err)
		}
		if h.Op != op || !h.Fin || h.RSV != 0 || h.Masked != masked || !bytes.Equal(p, payload) {
			t.Fatalf("header %+v payload %q, want op %#x masked %v payload %q", h, p, op, masked, payload)
		}
		if r.Buffered() != 0 {
			t.Fatalf("%d bytes left after the frame", r.Buffered())
		}
	})
}
