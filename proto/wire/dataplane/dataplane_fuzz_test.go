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

	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/protobuf/proto"
)

// countingReader counts the bytes a decoder consumed.
type countingReader struct {
	r io.Reader
	n int
}

// Read: io.Reader over r, counting. allow:wrapper
func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += n
	return n, err
}



// FuzzSendRecvRoundTrip: any frame Send writes, Recv reads back equal.
func FuzzSendRecvRoundTrip(f *testing.F) {
	f.Add("7", []byte("hello"), "", "", false, false)
	f.Add("7", []byte(nil), "agent", "localhost:22", true, false)
	f.Add("_heartbeat", []byte(nil), "", "", false, false)
	f.Add(strings.Repeat("s", 256), []byte("x"), "", "", false, true)
	f.Fuzz(func(t *testing.T, sid string, data []byte, agent, target string, open, closed bool) {
		want := &pb.TCPData{SessionId: sid, Data: data, AgentId: agent, TargetAddr: target, Open: open, Close: closed}
		var wire bytes.Buffer
		s := recordingV2(t, &wire)
		if err := s.Send(want); err != nil {
			return // proto.Marshal refuses invalid UTF-8 strings
		}
		if err := s.Flush(); err != nil {
			t.Fatal(err)
		}
		cr := &countingReader{r: bytes.NewReader(wire.Bytes())}
		got, err := scripted(t, cr, io.Discard).Recv()
		if err != nil {
			t.Fatalf("Recv of a sent frame: %v", err)
		}
		if !proto.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		if cr.n != wire.Len() {
			t.Fatalf("Recv consumed %d of %d bytes", cr.n, wire.Len())
		}
	})
}



// FuzzParseWindow: a CreditHeader value is accepted only as a decimal in
// the window range.
func FuzzParseWindow(f *testing.F) {
	for _, s := range []string{"262144", "0", "-1", "+5", "4294967296", "", " 1", strconv.Itoa(maxWindow + 1)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		w, err := ParseWindow(s)
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
			!strings.EqualFold(resp.Header.Get("Upgrade"), UpgradeToken) || m.c.Credit().PeerWindow() < minWindow || m.c.Credit().PeerWindow() > maxWindow {
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
