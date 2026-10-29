// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/link"
	"github.com/nfltr/relay/proto/pb"
	"google.golang.org/protobuf/proto"
)

var testToken = strings.Repeat("ab", 16)

// relayAuth verifies the bind token as the relay does (a token it issued).
type relayAuth struct{}

func (relayAuth) Hello(context.Context, tls.ConnectionState) (byte, []byte, error) {
	return 0, nil, errors.New("listener only")
}

func (relayAuth) Verify(_ context.Context, _ tls.ConnectionState, method byte, payload []byte) (link.Identity, error) {
	if method != link.MethodToken || string(payload) != testToken {
		return link.Identity{}, errors.New("unknown token")
	}
	return link.Identity{Method: "bind", Subject: "agent"}, nil
}

// v2pair binds an agent's data connection (Dial) and the relay's
// (link.Server, Wrap) over a TCP loopback connection.
func v2pair(t *testing.T) (agent, relay *Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	rc := make(chan *Conn, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			t.Error(err)
			rc <- nil
			return
		}
		c, id, err := link.Server(context.Background(), nc, link.Config{Window: testWindow, Auth: relayAuth{}})
		if err != nil || id.Subject != "agent" {
			t.Errorf("relay: %v %+v", err, id)
			rc <- nil
			return
		}
		rc <- Wrap(c)
	}()
	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	agent, err = Dial(context.Background(), nc, testToken, link.Config{Window: testWindow, Liveness: link.LivenessFast})
	if err != nil {
		t.Fatal(err)
	}
	relay = <-rc
	if relay == nil {
		t.FailNow()
	}
	t.Cleanup(func() { _ = agent.Close(); _ = relay.Close() })
	return agent, relay
}

// TestFramesRoundTripV2: every TCPData shape arrives as sent; an open and
// a bare close or half close travel as link frames.
func TestFramesRoundTripV2(t *testing.T) {
	{
		agent, relay := v2pair(t)
		sent := []*pb.TCPData{
			{SessionId: "7", AgentId: "agent", TargetAddr: "localhost:22", Open: true, E2Ee: true},
			{SessionId: "7", Data: []byte("hello")},
			{SessionId: "_heartbeat"},
			{SessionId: "_fingerprint", Data: []byte("ab:cd")},
			{SessionId: "9", Close: true, Half: true}, // a half close: link's half close frame
			{SessionId: "7", Close: true},
			{SessionId: "8", TargetAddr: "x", Close: true}, // not bare: a message
		}
		go func() {
			for _, f := range sent {
				if err := relay.Send(f); err != nil {
					t.Error(err)
				}
			}
			_ = relay.Flush()
		}()
		for i, w := range sent {
			got, err := agent.Recv()
			if err != nil {
				t.Fatalf("frame %d: %v", i, err)
			}
			if !proto.Equal(got, w) {
				t.Fatalf("frame %d: got %v, want %v", i, got, w)
			}
		}
	}
}

// TestV2OpenIsAnOpenFrame pins a version-2 open's encoding: an OPEN frame
// whose header is the TCPData without session id and open flag.
func TestV2OpenIsAnOpenFrame(t *testing.T) {
	var buf bytes.Buffer
	rec := recordingV2(t, &buf)
	if err := rec.Send(&pb.TCPData{SessionId: "s1", TargetAddr: "t:1", Open: true}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Send(&pb.TCPData{SessionId: "s1", Close: true}); err != nil {
		t.Fatal(err)
	}
	_ = rec.Flush()
	h, _ := proto.Marshal(&pb.TCPData{TargetAddr: "t:1"})
	want := append(append([]byte{0, 0, 0, byte(3 + len(h)), 3, 2, 's', '1'}, h...), 0, 0, 0, 4, 4, 2, 's', '1', 0)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("got % x\nwant % x", buf.Bytes(), want)
	}
}

// recordingV2 is a data connection that writes to w: a link handshake
// against a scripted reply.
func recordingV2(t testing.TB, w *bytes.Buffer) *Conn {
	t.Helper()
	c := scripted(t, nil, w)
	w.Reset() // the hello
	return c
}

// boundReply is a listener's reply that binds a data connection.
func boundReply() []byte {
	reply := []byte{0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	reply[6], reply[7] = byte(testWindow>>24), byte(testWindow>>16) // window, big endian
	reply[13] = 64                                                   // max sessions
	return reply
}

// scripted is a data connection bound by a scripted reply, that then
// reads r (nil: nothing) and writes w, the hello first.
func scripted(t testing.TB, r io.Reader, w io.Writer) *Conn {
	t.Helper()
	rd := io.Reader(bytes.NewReader(boundReply()))
	if r != nil {
		rd = io.MultiReader(rd, r)
	}
	c, err := Dial(context.Background(), closingConn{bufConn{r: rd, w: w}}, testToken, link.Config{Window: testWindow, Liveness: link.LivenessDatacenter})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// closingConn is a bufConn that a handshake and Close may use.
type closingConn struct{ bufConn }

// Close: no-op. allow:wrapper
func (closingConn) Close() error { return nil }

// SetDeadline: no-op. allow:wrapper
func (closingConn) SetDeadline(time.Time) error { return nil }

func TestPickVersion(t *testing.T) {
	for _, tc := range []struct {
		values []string
		want   int
	}{
		{nil, 0}, {[]string{"1"}, 0}, {[]string{"1", "2"}, 2}, {[]string{"2", "1"}, 2},
		{[]string{"1", "3"}, 0}, {[]string{"x"}, 0}, {[]string{" 2 "}, 2},
	} {
		if got := PickVersion(tc.values); got != tc.want {
			t.Fatalf("%q: %d, want %d", tc.values, got, tc.want)
		}
	}
}

func TestWindowFrame(t *testing.T) {
	sid, n, err := ParseWindowFrame(WindowFrame("s7", 1<<20))
	if err != nil || sid != "s7" || n != 1<<20 {
		t.Fatalf("%q %d %v", sid, n, err)
	}
	if _, _, err := ParseWindowFrame(&pb.TCPData{SessionId: WindowSID, Data: []byte{9}}); err == nil {
		t.Fatal("malformed window frame parsed")
	}
}

// TestFramesOnChainConnections: on a data connection that negotiated
// link.FeatureChain the relay's open is answered by the agent's first
// frame (link sends the ACCEPT), which Recv does not return: the agent's
// data and close follow its open, as on any connection.
func TestFramesOnChainConnections(t *testing.T) {
	agent, relay := v2pair(t)
	if err := relay.Send(&pb.TCPData{SessionId: "s", TargetAddr: "t:1", Open: true}); err != nil || relay.Flush() != nil {
		t.Fatal(err)
	}
	if f, err := agent.Recv(); err != nil || !f.GetOpen() {
		t.Fatalf("agent read %v, %v; want the open", f, err)
	}
	agent.Credit().Acquire("s", 2)
	for _, f := range []*pb.TCPData{{SessionId: "s", Data: []byte("hi")}, {SessionId: "s", Close: true}} {
		if err := agent.Send(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := agent.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"data", "close"} {
		f, err := relay.Recv()
		switch {
		case err != nil:
			t.Fatalf("relay read %v, want %s", err, want)
		case want == "data" && string(f.GetData()) != "hi", want == "close" && !f.GetClose():
			t.Fatalf("relay read %v, want %s", f, want)
		}
	}
}
