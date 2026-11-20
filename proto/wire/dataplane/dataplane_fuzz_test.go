// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// FuzzParseWindow: a CreditHeader value is accepted only as a decimal in
// the window range.
func FuzzParseWindow(f *testing.F) {
	for _, s := range []string{"262144", "0", "-1", "+5", "4294967296", "", " 1", strconv.Itoa(maxWindow + 1)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		w, err := parseWindow(s)
		if err != nil {
			return
		}
		if n, perr := strconv.ParseUint(s, 10, 32); perr != nil || int(n) != w || w < minWindow || w > maxWindow {
			t.Fatalf("accepted %q as window %d", s, w)
		}
	})
}

// FuzzUpgradeReply: the client's parser of the relay's upgrade answer
// takes only a 101 for UpgradeToken with nothing after it, followed by a
// link reply that binds, and reports any other status as a
// NoUpgradeError.
func FuzzUpgradeReply(f *testing.F) {
	ok := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + UpgradeToken + "\r\n\r\n"
	f.Add([]byte(ok), boundReply())
	f.Add([]byte(ok+"extra"), boundReply())
	f.Add([]byte(ok), []byte{1})
	f.Add([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+OldUpgradeToken+"\r\n\r\n"), boundReply())
	f.Add([]byte("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"), []byte(nil))
	f.Add([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"), []byte(nil))
	f.Add([]byte{}, []byte(nil))
	f.Fuzz(func(t *testing.T, reply, linkReply []byte) {
		nc := closingConn{bufConn{r: io.MultiReader(bytes.NewReader(reply), bytes.NewReader(linkReply)), w: io.Discard}}
		m, _, err := Upgrade(context.Background(), nc, "relay.test", "key", testWindow)
		// What Upgrade read: the answer may end inside linkReply.
		resp, perr := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(reply), bytes.NewReader(linkReply))), nil)
		var nu *NoUpgradeError
		if errors.As(err, &nu) && (perr != nil || nu.Status != resp.StatusCode) {
			t.Fatalf("NoUpgradeError %d from %q", nu.Status, reply)
		}
		if err != nil {
			return
		}
		_ = m.Close()
		if perr != nil || resp.StatusCode != http.StatusSwitchingProtocols ||
			!strings.EqualFold(resp.Header.Get("Upgrade"), UpgradeToken) {
			t.Fatalf("upgraded on %q", reply)
		}
	})
}

// FuzzReadAnswer: any bytes are an answer, which reads back the same, or
// ErrNoAnswer; never a panic, never more than the answer's own bytes.
func FuzzReadAnswer(f *testing.F) {
	f.Add(AppendAnswer(nil, 0, ""))
	f.Add(AppendAnswer(nil, 40, "no route to host"))
	f.Add([]byte{0, 3, 8, 7})
	f.Add([]byte{4, 1})
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bytes.NewReader(in)
		a, err := ReadAnswer(r)
		if err != nil {
			return
		}
		used := len(in) - r.Len()
		again, err := ReadAnswer(bytes.NewReader(AppendAnswer(nil, a.GetReason(), a.GetMessage())))
		if err != nil || again.GetReason() != a.GetReason() || (len(a.GetMessage()) <= MaxAnswer && again.GetMessage() != strings.ToValidUTF8(a.GetMessage(), "")) {
			t.Fatalf("answer %v (from %d bytes) reads back as %v, %v", a, used, again, err)
		}
	})
}
