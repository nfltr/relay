// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// STUN parsing
// ---------------------------------------------------------------------------

// legacyTxID is the transaction ID buildSTUNResponse writes.
var legacyTxID = [12]byte{'n', 'f', 'l', 't', 'r', '-', 'p', '2', 'p', '-', '0', '1'}

// buildSTUNResponse builds a minimal RFC 5389 Binding Success Response with
// one attribute.  aType is the attribute type code (0x0001 or 0x0020), ipStr
// is a dotted-decimal IPv4 address, port is the mapped port.
func buildSTUNResponse(t *testing.T, aType uint16, ipStr string, port int) []byte {
	t.Helper()
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		t.Fatalf("buildSTUNResponse: bad IP %q", ipStr)
	}

	// Attribute value: 1 byte zero, 1 byte family (0x01=IPv4), 2-byte port,
	// 4-byte IP.
	var attrVal [8]byte
	attrVal[0] = 0x00
	attrVal[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(attrVal[2:4], uint16(port))
	if aType == 0x0020 { // XOR-MAPPED-ADDRESS: XOR with magic cookie
		binary.BigEndian.PutUint16(attrVal[2:4], uint16(port)^0x2112)
		attrVal[4] = ip[0] ^ 0x21
		attrVal[5] = ip[1] ^ 0x12
		attrVal[6] = ip[2] ^ 0xa4
		attrVal[7] = ip[3] ^ 0x42
	} else {
		copy(attrVal[4:], ip)
	}

	// Attribute header: 2-byte type + 2-byte length.
	attrHeader := make([]byte, 4)
	binary.BigEndian.PutUint16(attrHeader[0:2], aType)
	binary.BigEndian.PutUint16(attrHeader[2:4], 8)
	attrHeader = append(attrHeader, attrVal[:]...)

	// Build STUN header.
	msgLen := len(attrHeader)
	packet := make([]byte, 20+msgLen)
	packet[0], packet[1] = 0x01, 0x01                                   // Binding Success Response
	binary.BigEndian.PutUint16(packet[2:4], uint16(msgLen))             // Length
	packet[4], packet[5], packet[6], packet[7] = 0x21, 0x12, 0xa4, 0x42 // Magic cookie
	copy(packet[8:], "nfltr-p2p-01")                                    // Transaction ID
	copy(packet[20:], attrHeader)
	return packet
}

func TestParseSTUNMappedAddr_XOR(t *testing.T) {
	t.Helper()
	pkt := buildSTUNResponse(t, 0x0020, "1.2.3.4", 4444)
	addr, err := parseSTUNMappedAddr(pkt, legacyTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "1.2.3.4:4444" {
		t.Fatalf("want 1.2.3.4:4444, got %s", addr)
	}
}

func TestParseSTUNMappedAddr_Fallback(t *testing.T) {
	pkt := buildSTUNResponse(t, 0x0001, "5.6.7.8", 9999)
	addr, err := parseSTUNMappedAddr(pkt, legacyTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "5.6.7.8:9999" {
		t.Fatalf("want 5.6.7.8:9999, got %s", addr)
	}
}

func TestParseSTUNMappedAddr_XORPreferred(t *testing.T) {
	// Packet contains MAPPED-ADDRESS first, then XOR-MAPPED-ADDRESS.
	ip1 := net.ParseIP("10.0.0.1").To4()
	ip2 := net.ParseIP("203.0.113.5").To4()
	buildAttr := func(aType uint16, ip net.IP, port int) []byte {
		var val [8]byte
		val[0] = 0x00
		val[1] = 0x01
		if aType == 0x0020 {
			binary.BigEndian.PutUint16(val[2:4], uint16(port)^0x2112)
			val[4] = ip[0] ^ 0x21
			val[5] = ip[1] ^ 0x12
			val[6] = ip[2] ^ 0xa4
			val[7] = ip[3] ^ 0x42
		} else {
			binary.BigEndian.PutUint16(val[2:4], uint16(port))
			copy(val[4:], ip)
		}
		h := make([]byte, 4)
		binary.BigEndian.PutUint16(h[0:2], aType)
		binary.BigEndian.PutUint16(h[2:4], 8)
		return append(h, val[:]...)
	}
	body := append(buildAttr(0x0001, ip1, 1111), buildAttr(0x0020, ip2, 2222)...)
	packet := make([]byte, 20+len(body))
	packet[0], packet[1] = 0x01, 0x01
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(body)))
	packet[4], packet[5], packet[6], packet[7] = 0x21, 0x12, 0xa4, 0x42
	copy(packet[8:], "nfltr-p2p-01")
	copy(packet[20:], body)
	addr, err := parseSTUNMappedAddr(packet, legacyTxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "203.0.113.5:2222" {
		t.Fatalf("want XOR addr 203.0.113.5:2222, got %s", addr)
	}
}

func TestParseSTUNMappedAddr_TooShort(t *testing.T) {
	_, err := parseSTUNMappedAddr([]byte{0x01, 0x01}, legacyTxID)
	if err == nil {
		t.Fatal("expected error for short packet")
	}
}

func TestParseSTUNMappedAddr_WrongMagicCookie(t *testing.T) {
	pkt := buildSTUNResponse(t, 0x0020, "1.2.3.4", 1234)
	pkt[4] = 0xFF // corrupt magic cookie
	_, err := parseSTUNMappedAddr(pkt, legacyTxID)
	if err == nil {
		t.Fatal("expected error for wrong magic cookie")
	}
}

func TestParseSTUNMappedAddr_WrongMessageType(t *testing.T) {
	pkt := buildSTUNResponse(t, 0x0020, "1.2.3.4", 1234)
	pkt[1] = 0x02 // change to non-success-response
	_, err := parseSTUNMappedAddr(pkt, legacyTxID)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

// ---------------------------------------------------------------------------
// HMAC handshake over loopback TCP
// ---------------------------------------------------------------------------

func TestHandshake_Success(t *testing.T) {
	token := testToken()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close() //nolint:errcheck
		_, hsErr := handshake(conn, token, "session-abc", false /* accepter */)
		errCh <- hsErr
	}()

	dialConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dialConn.Close() //nolint:errcheck

	ec, hsErr := handshake(dialConn, token, "session-abc", true /* dialer */)
	if hsErr != nil {
		t.Fatalf("dialer handshake: %v", hsErr)
	}
	if ec == nil {
		t.Fatal("dialer handshake returned nil conn")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("accepter handshake: %v", err)
	}
}

func TestHandshake_WrongToken(t *testing.T) {
	token1, token2 := testToken(), testToken()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	errCh := make(chan error, 1)
	go func() {
		conn, _ := ln.Accept()
		defer conn.Close() //nolint:errcheck
		// responder uses token2 (wrong)
		_, hsErr := handshake(conn, token2, "sess", false)
		errCh <- hsErr
	}()

	dialConn, _ := net.Dial("tcp", ln.Addr().String())
	defer dialConn.Close() //nolint:errcheck
	// initiator uses token1
	_, err1 := handshake(dialConn, token1, "sess", true)
	err2 := <-errCh

	if err1 == nil && err2 == nil {
		t.Fatal("handshake with mismatched tokens should have failed for at least one side")
	}
}

func TestHandshake_EncryptedDataExchange(t *testing.T) {
	token := testToken()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	type connResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan connResult, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- connResult{err: err}
			return
		}
		ec, hsErr := handshake(raw, token, "enc-test", false)
		if hsErr != nil {
			raw.Close() //nolint:errcheck
			ch <- connResult{err: hsErr}
			return
		}
		ch <- connResult{conn: ec}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	connA, err := handshake(raw, token, "enc-test", true)
	if err != nil {
		raw.Close() //nolint:errcheck
		t.Fatalf("dialer handshake: %v", err)
	}
	defer connA.Close() //nolint:errcheck

	r := <-ch
	if r.err != nil {
		t.Fatalf("accepter handshake: %v", r.err)
	}
	connB := r.conn
	defer connB.Close() //nolint:errcheck

	// Verify bidirectional encrypted exchange.
	msg1 := []byte("hello from dialer — this is encrypted")
	if _, err := connA.Write(msg1); err != nil {
		t.Fatalf("write A→B: %v", err)
	}
	buf := make([]byte, len(msg1))
	if _, err := io.ReadFull(connB, buf); err != nil {
		t.Fatalf("read A→B: %v", err)
	}
	if !bytes.Equal(buf, msg1) {
		t.Fatalf("A→B mismatch: got %q", buf)
	}

	msg2 := []byte("reply from accepter — also encrypted")
	if _, err := connB.Write(msg2); err != nil {
		t.Fatalf("write B→A: %v", err)
	}
	buf2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(connA, buf2); err != nil {
		t.Fatalf("read B→A: %v", err)
	}
	if !bytes.Equal(buf2, msg2) {
		t.Fatalf("B→A mismatch: got %q", buf2)
	}
}

// ---------------------------------------------------------------------------
// P2P frame encoding - writeFrame / readFrame
// ---------------------------------------------------------------------------

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frames := []*Frame{
		{Type: FrameChat, Text: "hello peer"},
		{Type: FrameFile, Name: "foo.txt", Size: 42, SHA256: "abc123"},
		{Type: FrameAck},
		{Type: FrameDone},
	}
	for _, f := range frames {
		if err := writeFrame(&buf, f); err != nil {
			t.Fatalf("writeFrame(%+v): %v", f, err)
		}
	}
	for i, want := range frames {
		got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("readFrame #%d: %v", i, err)
		}
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got)
		if string(wantJSON) != string(gotJSON) {
			t.Fatalf("frame %d mismatch: want %s, got %s", i, wantJSON, gotJSON)
		}
	}
}

// ---------------------------------------------------------------------------
// File transfer over loopback
// ---------------------------------------------------------------------------

func TestSendReceiveFile(t *testing.T) {
	// Create a temp source file.
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	content := []byte("p2p file transfer test content 12345")
	if err := os.WriteFile(src, content, 0600); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	// Pipe via loopback.
	server, client := loopbackPair(t)
	errCh := make(chan error, 1)
	go func() {
		defer server.Close() //nolint:errcheck
		_, e := ReceiveFile(server, outDir, nil)
		errCh <- e
	}()

	if err := SendFile(client, src, nil); err != nil {
		t.Fatalf("SendFile: %v", err)
	}
	client.Close() //nolint:errcheck

	if err := <-errCh; err != nil {
		t.Fatalf("ReceiveFile: %v", err)
	}

	received, err := os.ReadFile(filepath.Join(outDir, "src.txt"))
	if err != nil {
		t.Fatalf("read received file: %v", err)
	}
	if !bytes.Equal(received, content) {
		t.Fatalf("content mismatch: got %q", received)
	}
}

func TestSendReceiveDir(t *testing.T) {
	srcDir := t.TempDir()
	files := map[string]string{
		"a.txt":     "file alpha",
		"sub/b.txt": "file beta",
	}
	for rel, body := range files {
		full := filepath.Join(srcDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}

	outDir := t.TempDir()
	server, client := loopbackPair(t)
	errCh := make(chan error, 1)
	go func() {
		defer server.Close() //nolint:errcheck
		errCh <- ReceiveDir(server, outDir)
	}()

	if err := SendDir(client, srcDir, nil); err != nil {
		t.Fatalf("SendDir: %v", err)
	}
	client.Close() //nolint:errcheck

	if err := <-errCh; err != nil {
		t.Fatalf("ReceiveDir: %v", err)
	}

	base := filepath.Base(srcDir)
	for rel, want := range files {
		path := filepath.Join(outDir, base, rel)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != want {
			t.Fatalf("%s: want %q, got %q", rel, want, string(got))
		}
	}
}

func TestReceiveFile_PathTraversal(t *testing.T) {
	// A frame with a malicious path should be rejected.
	outDir := t.TempDir()
	server, client := loopbackPair(t)
	go func() {
		defer client.Close() //nolint:errcheck
		// Use ".." as the file name — filepath.Base("..") == ".." which
		// triggers the explicit guard in ReceiveFile.
		evil := &Frame{
			Type:   FrameFile,
			Name:   "..",
			Size:   5,
			SHA256: "",
		}
		_ = writeFrame(client, evil)
		_, _ = client.Write([]byte("haxxx"))
	}()

	_, err := ReceiveFile(server, outDir, nil)
	server.Close() //nolint:errcheck
	if err == nil {
		t.Fatal("expected path-traversal to be rejected")
	}
	if !strings.Contains(err.Error(), "path") && !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Connect - full round-trip over loopback (no STUN, no external network)
// ---------------------------------------------------------------------------

func TestConnect_Loopback(t *testing.T) {
	token := testToken()
	ctx := context.Background()

	// Peer A gathers candidates (no STUN - override the server to point
	// nowhere so the STUN step is skipped cleanly).
	origSTUN := STUNServer
	STUNServer = "127.0.0.1:1" // unreachable, so DiscoverExternalAddr will fail quickly
	t.Cleanup(func() { STUNServer = origSTUN })

	lnA, candidatesA, err := GatherCandidates(ctx)
	if err != nil {
		t.Fatalf("GatherCandidates A: %v", err)
	}
	lnB, candidatesB, err := GatherCandidates(ctx)
	if err != nil {
		lnA.Close() //nolint:errcheck
		t.Fatalf("GatherCandidates B: %v", err)
	}

	session := "test-session-1"
	sigA, sigB := streamPair() // the signaling stream: A dials, B answers
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := Connect(ctx, lnB, candidatesA, token, session, "responder", AwaitConn(sigB))
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}()

	connA, err := Connect(ctx, lnA, candidatesB, token, session, "initiator", AnnounceConn(sigA, session))
	if err != nil {
		t.Fatalf("Connect A: %v", err)
	}
	defer connA.Close() //nolint:errcheck

	select {
	case connB := <-connCh:
		defer connB.Close() //nolint:errcheck
		// Verify we can exchange data.
		msg := []byte("ping")
		if _, err := connA.Write(msg); err != nil {
			t.Fatalf("write ping: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := connB.Read(buf); err != nil {
			t.Fatalf("read ping: %v", err)
		}
		if !bytes.Equal(buf, msg) {
			t.Fatalf("want %q, got %q", msg, buf)
		}
	case err := <-errCh:
		t.Fatalf("Connect B: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// loopbackPair returns two ends of a connected TCP pipe over loopback.
func loopbackPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			ch <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() }) //nolint:errcheck
	server := <-ch
	t.Cleanup(func() { server.Close() }) //nolint:errcheck
	return server, client
}

// With no STUN server (nfltr p2p on a private relay) candidate gathering
// sends nothing to a third party: host candidates only.
func TestGatherCandidatesWithoutSTUNServer(t *testing.T) {
	saved := STUNServer
	t.Cleanup(func() { STUNServer = saved })
	STUNServer = ""
	if _, err := DiscoverExternalAddr(0); err != ErrSTUNOff {
		t.Fatalf("DiscoverExternalAddr with no server: %v, want ErrSTUNOff", err)
	}
	ln, cands, err := GatherCandidates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	host := GatherHostCandidates(ln.Addr().(*net.TCPAddr).Port)
	if len(cands) != len(host) {
		t.Fatalf("candidates %v, want the host candidates %v only", cands, host)
	}
}

// testToken is a random direct-channel secret (E2E.DirectToken in a session).
func testToken() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}
