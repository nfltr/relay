// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/nfltr/link"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
)

func TestAnswerRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := WriteAnswer(&b, relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED, "connection refused"); err != nil {
		t.Fatal(err)
	}
	b.WriteString("session bytes")
	a, err := ReadAnswer(&b)
	if err != nil || a.GetReason() != relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED || a.GetMessage() != "connection refused" {
		t.Fatalf("answer %v, %v", a, err)
	}
	if b.String() != "session bytes" {
		t.Fatalf("ReadAnswer read past the answer: %q left", b.String())
	}
	// An open session's answer: reason UNSPECIFIED, a long message cut.
	b.Reset()
	_ = WriteAnswer(&b, relayv1.ErrorReason_ERROR_REASON_UNSPECIFIED, strings.Repeat("é", MaxAnswer))
	if a, err := ReadAnswer(&b); err != nil || a.GetReason() != 0 || len(a.GetMessage()) > MaxAnswer {
		t.Fatalf("long answer %d bytes, %v", len(a.GetMessage()), err)
	}
	for _, in := range [][]byte{nil, {0}, {0, 5, 1}, {0xff, 0xff}, {0, 2, 0xff, 0xff}} {
		if _, err := ReadAnswer(bytes.NewReader(in)); !errors.Is(err, ErrNoAnswer) {
			t.Fatalf("ReadAnswer(%x) = %v, want ErrNoAnswer", in, err)
		}
	}
}

func TestNativeAnswers(t *testing.T) {
	a := Refusal(relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED, "connection refused")
	if !a.Refused || a.Code != link.CodeApp+7 || a.Msg != "connection refused" {
		t.Fatalf("Refusal: %+v", a)
	}
	if r, ok := AbortReason(a); !ok || r != relayv1.ErrorReason_ERROR_REASON_TARGET_REFUSED {
		t.Fatalf("AbortReason: %v, %v", r, ok)
	}
	if _, ok := AbortReason(&link.Abort{Code: link.CodeConnLost}); ok {
		t.Fatal("link's own code read as a reason")
	}
	if AnswerAbort(&relayv1.SessionAnswer{}) != nil {
		t.Fatal("an accepting in-band answer is a refusal")
	}
	in := &relayv1.SessionAnswer{Reason: relayv1.ErrorReason_ERROR_REASON_AGENT_OFFLINE, Message: "gone"}
	if got := AnswerAbort(in); got == nil || !got.Refused || got.Code != AbortCode(in.Reason) || got.Msg != "gone" {
		t.Fatalf("AnswerAbort(%v) = %+v", in, got)
	}
}
