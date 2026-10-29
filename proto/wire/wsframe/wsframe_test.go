// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package wsframe

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"
)

func maskBytewise(b []byte, key [4]byte) {
	for i := range b {
		b[i] ^= key[i%4]
	}
}

// TestFramesRoundTrip guards the framing both relay and CLI tunnels use:
// every length encoding, masked and not, reads back as written, and the
// word-wise mask equals RFC 6455's byte-wise one at every length.
func TestFramesRoundTrip(t *testing.T) {
	key := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	for _, n := range []int{0, 1, 7, 8, 9, 125, 126, 127, 65535, 65536, 70001} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		for _, k := range []*[4]byte{nil, &key} {
			wire := AppendFrame(nil, 0x2, payload, k)
			h, got, err := ReadFrame(bufio.NewReader(bytes.NewReader(wire)), 1<<20)
			if err != nil || !h.Fin || h.Op != 0x2 || h.Masked != (k != nil) || !bytes.Equal(got, payload) {
				t.Fatalf("n=%d masked=%v: h=%+v err=%v equal=%v", n, k != nil, h, err, bytes.Equal(got, payload))
			}
			if k != nil {
				want := bytes.Clone(payload)
				maskBytewise(want, key)
				if !bytes.Equal(wire[len(wire)-n:], want) {
					t.Fatalf("n=%d: word-wise mask differs from RFC 6455's", n)
				}
			}
		}
	}
}

func TestReadFrameErrors(t *testing.T) {
	big := AppendHeader(nil, 0x2, 2<<20, nil)
	if _, _, err := ReadFrame(bufio.NewReader(bytes.NewReader(big)), 1<<20); err == nil {
		t.Fatal("a frame over max must fail")
	}
	if _, _, err := ReadFrame(bufio.NewReader(bytes.NewReader(nil)), 1<<20); err != io.EOF {
		t.Fatalf("empty stream: %v, want io.EOF", err)
	}
	cut := AppendFrame(nil, 0x2, make([]byte, 300), nil)[:3]
	if _, _, err := ReadFrame(bufio.NewReader(bytes.NewReader(cut)), 1<<20); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated header: %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestReadHeaderAllocates nothing: the per-frame header reads used to
// allocate up to three slices.
func TestReadHeaderAllocatesNothing(t *testing.T) {
	key := [4]byte{1, 2, 3, 4}
	wire := AppendHeader(nil, 0x2, 70000, &key)
	rd := bytes.NewReader(wire)
	br := bufio.NewReader(rd)
	allocs := testing.AllocsPerRun(100, func() {
		rd.Reset(wire)
		br.Reset(rd)
		if _, err := ReadHeader(br); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("ReadHeader allocates %.0f times per frame", allocs)
	}
}

func BenchmarkMask(b *testing.B) {
	buf := make([]byte, 32<<10)
	key := [4]byte{1, 2, 3, 4}
	b.Run("wordwise", func(b *testing.B) {
		b.SetBytes(int64(len(buf)))
		for b.Loop() {
			Mask(buf, key)
		}
	})
	b.Run("bytewise", func(b *testing.B) {
		b.SetBytes(int64(len(buf)))
		for b.Loop() {
			maskBytewise(buf, key)
		}
	})
}

// frame builds one raw frame: fin, rsv bits, opcode, payload, masked.
func frame(fin bool, rsv, op byte, payload []byte) []byte {
	key := [4]byte{1, 2, 3, 4}
	b := AppendFrame(nil, op, payload, &key)
	if !fin {
		b[0] &^= 0x80
	}
	b[0] |= rsv << 4
	return b
}

func readAll(wire []byte, max int64) (ops []byte, msgs []string, err error) {
	var m MessageReader
	r := bufio.NewReader(bytes.NewReader(wire))
	for {
		op, p, err := m.ReadMessage(r, max)
		if err != nil {
			return ops, msgs, err
		}
		ops, msgs = append(ops, op), append(msgs, string(p))
	}
}

// TestMessageReaderInterleavedControl guards the data loss Autobahn 5.6-5.8
// and 5.19-5.20 found: a ping between a message's fragments used to replace
// the message's opcode and swallow its fragments into the ping's payload.
func TestMessageReaderInterleavedControl(t *testing.T) {
	wire := slices.Concat(
		frame(false, 0, 0x2, []byte("frag")),
		frame(true, 0, 0x9, []byte("ping")),
		frame(false, 0, 0x0, []byte("ment")),
		frame(true, 0, 0xA, nil),
		frame(true, 0, 0x0, []byte("ed")),
		frame(true, 0, 0x1, []byte("whole")),
	)
	ops, msgs, err := readAll(wire, 1<<20)
	if err != io.EOF || !bytes.Equal(ops, []byte{0x9, 0xA, 0x2, 0x1}) ||
		!slices.Equal(msgs, []string{"ping", "", "fragmented", "whole"}) {
		t.Fatalf("ops %v msgs %q err %v", ops, msgs, err)
	}
}

// TestMessageReaderViolations: every RFC 6455 framing violation Autobahn
// sections 2-7 probe fails the connection with its close code.
func TestMessageReaderViolations(t *testing.T) {
	long := bytes.Repeat([]byte{'a'}, 126)
	for _, tc := range []struct {
		name string
		wire []byte
		code uint16
	}{
		{"reserved bits", frame(true, 1, 0x2, nil), CloseProtocolError},
		{"reserved data opcode", frame(true, 0, 0x3, nil), CloseProtocolError},
		{"reserved control opcode", frame(true, 0, 0xB, nil), CloseProtocolError},
		{"fragmented ping", frame(false, 0, 0x9, nil), CloseProtocolError},
		{"ping over 125 bytes", frame(true, 0, 0x9, long), CloseProtocolError},
		{"continuation without a message", frame(true, 0, 0x0, []byte("x")), CloseProtocolError},
		{"data frame inside a fragmented message", slices.Concat(frame(false, 0, 0x1, []byte("a")), frame(true, 0, 0x1, []byte("b"))), CloseProtocolError},
		{"invalid UTF-8 text", frame(true, 0, 0x1, []byte{0xce, 0xba, 0xff}), CloseInvalidPayload},
		{"invalid UTF-8 across fragments", slices.Concat(frame(false, 0, 0x1, []byte{0xce}), frame(true, 0, 0x0, []byte{0x41})), CloseInvalidPayload},
		{"1-byte close payload", frame(true, 0, 0x8, []byte{3}), CloseProtocolError},
		{"close code 1005", frame(true, 0, 0x8, ClosePayload(1005)), CloseProtocolError},
		{"close code 2999", frame(true, 0, 0x8, ClosePayload(2999)), CloseProtocolError},
		{"invalid UTF-8 close reason", frame(true, 0, 0x8, append(ClosePayload(1000), 0xff)), CloseInvalidPayload},
		{"fragmented message over max", slices.Concat(frame(false, 0, 0x2, make([]byte, 150)), frame(true, 0, 0x0, make([]byte, 60))), CloseTooBig},
		{"frame over max", frame(true, 0, 0x2, make([]byte, 201)), CloseTooBig},
	} {
		_, _, err := readAll(tc.wire, 200)
		if ce, ok := errors.AsType[*CloseError](err); !ok || ce.Code != tc.code {
			t.Errorf("%s: err %v, want close code %d", tc.name, err, tc.code)
		}
	}
	// Valid: fragmented UTF-8 split inside a code point, close codes 1000 and 4999.
	wire := slices.Concat(frame(false, 0, 0x1, []byte{0xce}), frame(true, 0, 0x0, []byte{0xba}),
		frame(true, 0, 0x8, ClosePayload(1000)), frame(true, 0, 0x8, append(ClosePayload(4999), "bye"...)))
	if ops, _, err := readAll(wire, 100); err != io.EOF || len(ops) != 3 {
		t.Fatalf("valid stream: ops %v err %v", ops, err)
	}
}
