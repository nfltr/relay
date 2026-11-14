// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package dgram is a datagram association (nfltr
// docs/decisions/nf1-udp-2026-11-14.md section 2): many flows of one
// datagram service inside one session of its target (an nf1 session, an
// organisation session, an account session to a udp service), relayed.
// The session's bytes are frames: one type byte, then uvarints.
//
//	O id len payload  open flow id (the next unused id) with its first datagram
//	A id              the agent accepts flow id
//	R id reason       the agent refuses flow id (past max_flows, target unreachable)
//	D id len payload  a datagram of flow id, len 0..65535
//	C id reason       close flow id (idle, the backstop, the target's socket failed)
//
// A frame for an id never opened is a protocol error that ends the
// association; for an id closed it is dropped (counted Closed). Readers
// never wait: every overflow is a counted drop. The lifecycle is relay
// spec/DatagramAssoc.tla's; a run's trace (-tags relaytrace) is checked
// against spec/TraceDatagramAssoc.tla (spec/README.md).
package dgram

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame types.
const (
	frameOpen   = 'O'
	frameAccept = 'A'
	frameRefuse = 'R'
	frameData   = 'D'
	frameClose  = 'C'
)

// MaxDatagram is the largest datagram a frame carries (the length's bound).
const MaxDatagram = 65535

// Reason is why a flow was refused or closed (R, C).
type Reason uint64

const (
	ReasonIdle        Reason = 1 // the client's flow idle timer
	ReasonBackstop    Reason = 2 // the agent's idle backstop
	ReasonTarget      Reason = 3 // the target's socket failed
	ReasonFull        Reason = 4 // past the agent's max_flows
	ReasonUnreachable Reason = 5 // the target could not be dialled
	ReasonClosed      Reason = 6 // its side closed it (Flow.Close)
)

// ErrProtocol: the peer sent a malformed frame or one for an id never
// opened; the association ends.
var ErrProtocol = errors.New("dgram: protocol error")

type frame struct {
	typ     byte
	id      uint64
	reason  Reason
	payload []byte
}

// appendFrame encodes f.
func appendFrame(b []byte, f frame) []byte {
	b = append(b, f.typ)
	b = binary.AppendUvarint(b, f.id)
	switch f.typ {
	case frameOpen, frameData:
		b = binary.AppendUvarint(b, uint64(len(f.payload)))
		b = append(b, f.payload...)
	case frameRefuse, frameClose:
		b = binary.AppendUvarint(b, uint64(f.reason))
	}
	return b
}

// readFrame decodes one frame from r; a payload is read into buf (at least
// MaxDatagram bytes) and aliases it until the next call.
func readFrame(r *bufio.Reader, buf []byte) (frame, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return frame{}, err
	}
	f := frame{typ: typ}
	if f.id, err = uvarint(r); err != nil {
		return frame{}, err
	}
	if f.id == 0 {
		return frame{}, fmt.Errorf("%w: flow id 0", ErrProtocol)
	}
	switch typ {
	case frameOpen, frameData:
		n, err := uvarint(r)
		if err != nil {
			return frame{}, err
		}
		if n > MaxDatagram {
			return frame{}, fmt.Errorf("%w: datagram of %d bytes", ErrProtocol, n)
		}
		f.payload = buf[:n]
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return frame{}, unexpected(err)
		}
	case frameRefuse, frameClose:
		n, err := uvarint(r)
		if err != nil {
			return frame{}, err
		}
		f.reason = Reason(n)
	case frameAccept:
	default:
		return frame{}, fmt.Errorf("%w: frame type %#x", ErrProtocol, typ)
	}
	return f, nil
}

func uvarint(r *bufio.Reader) (uint64, error) {
	v, err := binary.ReadUvarint(r)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	return v, nil
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
