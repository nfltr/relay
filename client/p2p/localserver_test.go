// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/nfltr/relay/proto/wire/turnwire"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCallServer_BindsLoopback(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	srv, err := NewCallServer(NewSignalConn(TCPPath(a)), "initiator", "stun.l.google.com:19302", func() string {
		return "<html>test</html>"
	})
	if err != nil {
		t.Fatalf("NewCallServer: %v", err)
	}
	defer srv.Close()

	addr := srv.listener.Addr().String()
	host, _, _ := net.SplitHostPort(addr)
	if host != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1, got %s", host)
	}
}

func TestCallServer_URLContainsTokenAndRole(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	srv, err := NewCallServer(NewSignalConn(TCPPath(a)), "responder", "stun.example.com:19302", func() string {
		return "<html></html>"
	})
	if err != nil {
		t.Fatalf("NewCallServer: %v", err)
	}
	defer srv.Close()

	url := srv.URL()
	if !strings.Contains(url, "token=") {
		t.Error("URL missing token param")
	}
	if !strings.Contains(url, "role=responder") {
		t.Error("URL missing role=responder param")
	}
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Errorf("URL should start with http://127.0.0.1:, got %s", url)
	}
}

func TestCallServer_PageRequiresToken(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	srv, err := NewCallServer(NewSignalConn(TCPPath(a)), "initiator", "stun.l.google.com:19302", func() string {
		return "<html>call page</html>"
	})
	if err != nil {
		t.Fatalf("NewCallServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)                   //nolint:errcheck
	time.Sleep(50 * time.Millisecond) // let server start

	baseURL := fmt.Sprintf("http://%s", srv.listener.Addr())

	// Without token → 403.
	resp, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 without token, got %d", resp.StatusCode)
	}

	// With wrong token → 403.
	resp, err = http.Get(baseURL + "/?token=wrong")
	if err != nil {
		t.Fatalf("GET /?token=wrong: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 with wrong token, got %d", resp.StatusCode)
	}

	// With correct token → 200.
	resp, err = http.Get(srv.URL())
	if err != nil {
		t.Fatalf("GET URL: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with correct token, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "call page") {
		t.Error("page body missing expected content")
	}

	cancel()
}

func TestCallServer_STUNTemplateReplacement(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	srv, err := NewCallServer(NewSignalConn(TCPPath(a)), "initiator", "my-custom-stun:3478", func() string {
		return "<html>stun={{STUN_SERVER}}</html>"
	})
	if err != nil {
		t.Fatalf("NewCallServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx) //nolint:errcheck
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(srv.URL())
	if err != nil {
		t.Fatalf("GET URL: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck
	if !strings.Contains(string(body), "stun=my-custom-stun:3478") {
		t.Error("STUN server not substituted in HTML")
	}

	cancel()
}

// TestCallServer_TURNTemplate: with no TURN the placeholder is empty (the
// page keeps STUN only); with TURN it carries the servers as base64 JSON.
func TestCallServer_TURNTemplate(t *testing.T) {
	page := func(turn []turnwire.ICEServer) string {
		a, b := net.Pipe()
		defer a.Close() //nolint:errcheck
		defer b.Close() //nolint:errcheck
		srv, err := NewCallServer(NewSignalConn(TCPPath(a)), "initiator", "stun:3478", func() string { return "turn='{{TURN_SERVERS}}'" })
		if err != nil {
			t.Fatal(err)
		}
		srv.TURN = turn
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go srv.Run(ctx) //nolint:errcheck
		time.Sleep(50 * time.Millisecond)
		resp, err := http.Get(srv.URL())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close() //nolint:errcheck
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	if got := page(nil); got != "turn=''" {
		t.Fatalf("no TURN: %q", got)
	}
	want := []turnwire.ICEServer{{URLs: []string{"turn:10.0.0.1:3478?transport=udp"}, Username: "1:a", Credential: `c'"</script>`}}
	got := page(want)
	enc := strings.TrimSuffix(strings.TrimPrefix(got, "turn='"), "'")
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("not base64: %q", got)
	}
	var back []turnwire.ICEServer
	if err := json.Unmarshal(raw, &back); err != nil || len(back) != 1 || back[0].Credential != want[0].Credential || back[0].URLs[0] != want[0].URLs[0] {
		t.Fatalf("round trip: %s %v", raw, err)
	}
}

// TestCallServer_PeerGoneEndsCall: when the P2P connection closes without a
// FrameDone (the peer exited first, a relayed stream ended), the page is
// still told the call ended.
func TestCallServer_PeerGoneEndsCall(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close() //nolint:errcheck
	srv, err := NewCallServer(NewSignalConn(TCPPath(a)), "responder", "", func() string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	go srv.Run(ctx) //nolint:errcheck

	c, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "GET /ws?token=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", srv.token, srv.listener.Addr())
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	if f, err := readFrame(b); err != nil || f.Type != FrameRTCReady {
		t.Fatalf("want rtc-ready from the server, got %v %v", f, err)
	}
	_ = b.Close() // the peer is gone, no FrameDone

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		t.Fatalf("no message after the peer left: %v", err)
	}
	msg := make([]byte, hdr[1]&0x7f)
	if _, err := io.ReadFull(br, msg); err != nil || string(msg) != `{"type":"hangup"}` {
		t.Fatalf("page got %q (%v), want hangup", msg, err)
	}
}

func TestCallServer_WSRequiresToken(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	srv, err := NewCallServer(NewSignalConn(TCPPath(a)), "initiator", "stun.l.google.com:19302", func() string {
		return "<html></html>"
	})
	if err != nil {
		t.Fatalf("NewCallServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx) //nolint:errcheck
	time.Sleep(50 * time.Millisecond)

	baseURL := fmt.Sprintf("http://%s", srv.listener.Addr())

	// WS upgrade without token → 403.
	resp, err := http.Get(baseURL + "/ws")
	if err != nil {
		t.Fatalf("GET /ws: %v", err)
	}
	resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for /ws without token, got %d", resp.StatusCode)
	}

	cancel()
}

func TestFrameRTC_RoundTrip(t *testing.T) {
	// Verify FrameRTC frame can be written and read back.
	a, b := net.Pipe()
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	msg := `{"type":"sdp-offer","sdp":{"type":"offer","sdp":"v=0\r\n..."}}`
	go func() {
		_ = writeFrame(a, &Frame{Type: FrameRTC, Text: msg})
	}()

	f, err := readFrame(b)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if f.Type != FrameRTC {
		t.Errorf("expected FrameRTC, got %q", f.Type)
	}
	if f.Text != msg {
		t.Errorf("text mismatch: got %q", f.Text)
	}
}

func TestFrameRTCReady_RoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	go func() {
		_ = writeFrame(a, &Frame{Type: FrameRTCReady})
	}()

	f, err := readFrame(b)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if f.Type != FrameRTCReady {
		t.Errorf("expected FrameRTCReady, got %q", f.Type)
	}
}

func TestFrameTypes_JSONMarshal(t *testing.T) {
	cases := []struct {
		ft   FrameType
		want string
	}{
		{FrameRTC, `"rtc"`},
		{FrameRTCReady, `"rtc-ready"`},
	}
	for _, tc := range cases {
		f := Frame{Type: tc.ft}
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal %v: %v", tc.ft, err)
		}
		if !strings.Contains(string(b), tc.want) {
			t.Errorf("JSON for %v should contain %s, got %s", tc.ft, tc.want, string(b))
		}
	}
}
