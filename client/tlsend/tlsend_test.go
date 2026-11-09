// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package tlsend

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// The end of a TLS stream is the peer's only with its close_notify: a
// transport that ends between two records (a relay cutting the session)
// reads as ErrTruncated, never io.EOF, on either side (claims review
// CLAIMS-A Q5; spec/proverif/README.md e2ee_tcp queries 11-12).
func TestRawEndIsTruncation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cut     bool // the transport closed under the writer, no close_notify
		wantErr error
	}{
		{"close_notify", false, nil},
		{"cut", true, ErrTruncated},
	} {
		for _, readerIsServer := range []bool{false, true} {
			reader, writer, writerRaw := pair(t, readerIsServer)
			go func() {
				_, _ = writer.Write([]byte("hello"))
				if tc.cut {
					_ = writerRaw.Close()
				} else {
					_ = writer.CloseWrite()
				}
			}()
			got, err := io.ReadAll(reader)
			if string(got) != "hello" || !errors.Is(err, tc.wantErr) {
				t.Errorf("%s, reader server %v: read %q, %v; want %q, %v", tc.name, readerIsServer, got, err, "hello", tc.wantErr)
			}
		}
	}
}

// pair is a TLS connection over loopback TCP: the reader wrapped
// (Client or Server), the writer plain crypto/tls, and the writer's
// transport.
func pair(t *testing.T, readerIsServer bool) (reader *Conn, writer *tls.Conn, writerRaw net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc := <-accepted
	t.Cleanup(func() { _ = cc.Close(); _ = sc.Close() })
	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert(t)}, MinVersion: tls.VersionTLS13}
	cliCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13} // #nosec G402 -- test: the test's own certificate
	var hs func() error
	if readerIsServer {
		reader, writer, writerRaw = Server(sc, srvCfg), tls.Client(cc, cliCfg), cc
		hs = writer.Handshake
	} else {
		reader, writer, writerRaw = Client(cc, cliCfg), tls.Server(sc, srvCfg), sc
		hs = writer.Handshake
	}
	done := make(chan error, 1)
	go func() { done <- hs() }()
	if err := reader.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return reader, writer, writerRaw
}

func cert(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}
