// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nfltr/link"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"google.golang.org/protobuf/proto"
)

// A session's answer: whether the far side took the session (its agent
// reached the target) or why not, a nfltr.relay.v1.ErrorReason and a
// message. pb.TCPData.Answer marks an owner's /connect session, whose
// opener waits for the far side's answer.
//
// On a leg whose two sides negotiated link.FeatureChain (link v0.10.0:
// data connections, agent links over TCP, QUIC links that negotiated
// quiclink.ALPNChain, the replica link) the answer is link's own: the
// accepter's Accept, or a refusal (Refusal, link.Abort.Refused) whose
// code is AbortCode(reason); a reset after the open carries a code too.
//
// On any other leg (gRPC and data connection frame streams, which are not
// link sessions, and a peer that does not announce FeatureChain: nfltr
// before v2.2.0, nfltr-relay before v0.22.0) the answer is in band, as
// before: the first bytes the far side sends on a session whose open asked
// for one, a 2-byte big-endian length and a nfltr.relay.v1.SessionAnswer.
// Hops pass it on as session bytes; each answers only its own refusal.

// AnswerHeader is the ConnectTCP request metadata in which an agent
// announces that it answers opens that ask for it, and the header of a
// relay's 101 to a data connection upgrade saying it does the same for
// the client's sessions. Its value is "1".
const AnswerHeader = "x-nfltr-session-answer"

// MaxAnswer bounds an answer's message (its encoding stays below 1 KiB).
const MaxAnswer = 512

const maxAnswerFrame = 1024

// ErrNoAnswer is ReadAnswer's error for a session that ended before its
// answer, or whose first bytes are no answer.
var ErrNoAnswer = errors.New("dataplane: the session ended without an answer")

// AppendAnswer appends the answer with reason and msg (cut to MaxAnswer
// bytes of valid UTF-8) to b.
func AppendAnswer(b []byte, reason relayv1.ErrorReason, msg string) []byte {
	if len(msg) > MaxAnswer {
		msg = msg[:MaxAnswer]
	}
	msg = strings.ToValidUTF8(msg, "")
	body, err := proto.Marshal(&relayv1.SessionAnswer{Reason: reason, Message: msg})
	if err != nil { // a valid string and an enum always marshal
		panic(err)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(body))) // #nosec G115 -- at most maxAnswerFrame: MaxAnswer bytes of message and an enum
	return append(b, body...)
}

// WriteAnswer writes the answer with reason and msg to w in one write.
func WriteAnswer(w io.Writer, reason relayv1.ErrorReason, msg string) error {
	_, err := w.Write(AppendAnswer(nil, reason, msg))
	return err
}

// ReadAnswer reads a session's answer from r and nothing more.
func ReadAnswer(r io.Reader) (*relayv1.SessionAnswer, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNoAnswer
		}
		return nil, err
	}
	n := binary.BigEndian.Uint16(h[:])
	if n > maxAnswerFrame {
		return nil, fmt.Errorf("%w: a %d-byte answer", ErrNoAnswer, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNoAnswer
		}
		return nil, err
	}
	a := &relayv1.SessionAnswer{}
	if err := proto.Unmarshal(body, a); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoAnswer, err)
	}
	return a, nil
}

// AbortCode is reason's code in a link abort (link.CodeApp + reason): the
// answer's reason on a leg that negotiated link.FeatureChain.
func AbortCode(reason relayv1.ErrorReason) uint32 {
	return link.CodeApp + uint32(reason) // #nosec G115 -- ErrorReason values are small and non-negative
}

// Refusal is the refusal of an open with reason and msg on a leg that
// negotiated link.FeatureChain (link.Session.AbortWith, a Route's error).
func Refusal(reason relayv1.ErrorReason, msg string) *link.Abort {
	return &link.Abort{Refused: true, Code: AbortCode(reason), Msg: msg}
}

// AbortReason is the reason a link abort carries (AbortCode), false when
// its code is link's own (link.CodeConnLost, link.CodeDraining, ...).
func AbortReason(a *link.Abort) (relayv1.ErrorReason, bool) {
	if a == nil || a.Code < link.CodeApp {
		return 0, false
	}
	return relayv1.ErrorReason(a.Code - link.CodeApp), true // #nosec G115 -- a code from AbortCode
}

// AnswerAbort is an in-band answer as a link refusal: nil when it took
// the session (reason UNSPECIFIED). A hop between an in-band leg and a
// FeatureChain leg passes the answer on with it.
func AnswerAbort(a *relayv1.SessionAnswer) *link.Abort {
	if a.GetReason() == relayv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
		return nil
	}
	return Refusal(a.GetReason(), a.GetMessage())
}
