// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// generateSelfSignedCert
// ---------------------------------------------------------------------------

func TestGenerateSelfSignedCert_ValidCert(t *testing.T) {
	t.Helper()
	cert, fp, err := generateSelfSignedCert("test-agent")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
	if fp == "" {
		t.Fatal("fingerprint is empty")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse DER: %v", err)
	}

	if leaf.Subject.CommonName != "test-agent" {
		t.Errorf("CN = %q, want test-agent", leaf.Subject.CommonName)
	}

	found := slices.Contains(leaf.DNSNames, "test-agent")
	if !found {
		t.Errorf("DNSNames = %v, want to contain test-agent", leaf.DNSNames)
	}

	now := time.Now()
	if leaf.NotBefore.After(now) {
		t.Error("NotBefore is in the future")
	}
	if leaf.NotAfter.Before(now.Add(364 * 24 * time.Hour)) {
		t.Errorf("NotAfter = %v, expected at least ~1 year from now", leaf.NotAfter)
	}

	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("missing KeyUsageDigitalSignature")
	}

	hasServerAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("missing ExtKeyUsageServerAuth")
	}
}

func TestGenerateSelfSignedCert_FingerprintFormat(t *testing.T) {
	t.Helper()
	_, fp, err := generateSelfSignedCert("fp-test")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}

	// SHA-256 = 32 bytes → 32 hex pairs separated by colons = 95 chars.
	if len(fp) != 95 {
		t.Errorf("fingerprint length = %d, want 95, fp = %s", len(fp), fp)
	}

	parts := strings.Split(fp, ":")
	if len(parts) != 32 {
		t.Errorf("fingerprint parts = %d, want 32", len(parts))
	}

	for i, p := range parts {
		if len(p) != 2 {
			t.Errorf("part[%d] = %q, want 2 chars", i, p)
		}
		for _, c := range p {
			if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
				t.Errorf("part[%d] = %q, contains non-hex char %c", i, p, c)
			}
		}
	}
}

func TestGenerateSelfSignedCert_UniquePerCall(t *testing.T) {
	t.Helper()
	_, fp1, _ := generateSelfSignedCert("agent-a")
	_, fp2, _ := generateSelfSignedCert("agent-b")
	if fp1 == fp2 {
		t.Error("two certificates have the same fingerprint")
	}
}

// ---------------------------------------------------------------------------
// formatFingerprint
// ---------------------------------------------------------------------------

func TestFormatFingerprint(t *testing.T) {
	t.Helper()
	cases := []struct {
		name string
		hash []byte
		want string
	}{
		{
			name: "two_bytes",
			hash: []byte{0xAB, 0xCD},
			want: "AB:CD",
		},
		{
			name: "zeros",
			hash: []byte{0x00, 0x00, 0x00},
			want: "00:00:00",
		},
		{
			name: "single_byte",
			hash: []byte{0xFF},
			want: "FF",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatFingerprint(tc.hash)
			if got != tc.want {
				t.Errorf("formatFingerprint = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// loadCertFromFiles
// ---------------------------------------------------------------------------

func TestLoadCertFromFiles_ValidPEM(t *testing.T) {
	t.Helper()

	cert, origFP, err := generateSelfSignedCert("load-test")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	writeCertAndKeyPEM(t, cert, certFile, keyFile)

	loaded, loadedFP, err := loadCertFromFiles(certFile, keyFile)
	if err != nil {
		t.Fatalf("loadCertFromFiles: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded cert is nil")
	}
	if loadedFP != origFP {
		t.Errorf("fingerprint mismatch: loaded=%s orig=%s", loadedFP, origFP)
	}
}

func TestLoadCertFromFiles_BadPath(t *testing.T) {
	t.Helper()
	_, _, err := loadCertFromFiles("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent files")
	}
}

// ---------------------------------------------------------------------------
// newE2EETLSConfig
// ---------------------------------------------------------------------------

func TestNewE2EETLSConfig(t *testing.T) {
	t.Helper()
	cert, _, err := generateSelfSignedCert("config-test")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cfg := newE2EETLSConfig(cert, "config-test")
	if cfg == nil {
		t.Fatal("config is nil")
	}
	if cfg.tlsConfig == nil {
		t.Fatal("tlsConfig is nil")
	}
	if cfg.Fingerprint() == "" {
		t.Fatal("fingerprint is empty")
	}
	if cfg.tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", cfg.tlsConfig.MinVersion, tls.VersionTLS12)
	}
	if cfg.tlsConfig.GetCertificate == nil {
		t.Fatal("GetCertificate callback is nil")
	}

	fp := sha256.Sum256(cert.Certificate[0])
	expectedFP := formatFingerprint(fp[:])
	if cfg.Fingerprint() != expectedFP {
		t.Errorf("fingerprint = %s, want %s", cfg.Fingerprint(), expectedFP)
	}
}

// ---------------------------------------------------------------------------
// TLS handshake integration test
// ---------------------------------------------------------------------------

func TestE2EE_TLSHandshake(t *testing.T) {
	t.Helper()

	cert, fp, err := generateSelfSignedCert("handshake-test")
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	cfg := newE2EETLSConfig(cert, "handshake-test")

	clientConn, serverConn := net.Pipe()

	errCh := make(chan error, 1)
	go func() {
		tlsServer := tls.Server(serverConn, cfg.tlsConfig)
		defer func() { _ = tlsServer.Close() }()
		if hsErr := tlsServer.Handshake(); hsErr != nil {
			errCh <- hsErr
			return
		}
		buf := make([]byte, 256)
		n, readErr := tlsServer.Read(buf)
		if readErr != nil {
			errCh <- readErr
			return
		}
		if _, writeErr := tlsServer.Write(buf[:n]); writeErr != nil {
			errCh <- writeErr
			return
		}
		errCh <- nil
	}()

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	tlsClient := tls.Client(clientConn, &tls.Config{
		ServerName: "handshake-test",
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	defer func() { _ = tlsClient.Close() }()

	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	state := tlsClient.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	serverFP := sha256.Sum256(state.PeerCertificates[0].Raw)
	gotFP := formatFingerprint(serverFP[:])
	if gotFP != fp {
		t.Errorf("server fingerprint = %s, want %s", gotFP, fp)
	}

	msg := []byte("hello e2ee")
	if _, err := tlsClient.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 256)
	n, err := tlsClient.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello e2ee" {
		t.Errorf("echo = %q, want %q", string(buf[:n]), "hello e2ee")
	}

	if srvErr := <-errCh; srvErr != nil {
		t.Errorf("server error: %v", srvErr)
	}
}

// TestE2EETLSNegotiatesPostQuantum: both E2EE server configs (self-signed and
// ACME) negotiate the hybrid post-quantum X25519MLKEM768 with a default Go
// client, as the CLI's E2EE dialers are.
func TestE2EETLSNegotiatesPostQuantum(t *testing.T) {
	cert, _, err := generateSelfSignedCert("pq-test")
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	acme, err := newACMEE2EEConfig(ACMEConfig{Domains: []string{"pq.example.com"}, CacheDir: t.TempDir()}, "pq-acme",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("acme config: %v", err)
	}
	acmeTLS := acme.tlsConfig.Clone()
	acmeTLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }
	for name, serverCfg := range map[string]*tls.Config{
		"self-signed": newE2EETLSConfig(cert, "pq-test").tlsConfig,
		"acme":        acmeTLS,
	} {
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer func() { _ = clientConn.Close(); _ = serverConn.Close() }()
			go func() { _ = tls.Server(serverConn, serverCfg).Handshake() }()
			client := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // only the key exchange is under test
			if err := client.Handshake(); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if got := client.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
				t.Fatalf("negotiated %v, want X25519MLKEM768", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// singleConnListener
// ---------------------------------------------------------------------------

func TestSingleConnListener_AcceptOnce(t *testing.T) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	ln := &singleConnListener{conn: c1, done: make(chan struct{})}

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if conn != c1 {
		t.Error("first accept returned wrong conn")
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	_, err = ln.Accept()
	if err == nil {
		t.Error("second accept should return error")
	}
}

func TestSingleConnListener_Addr(t *testing.T) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	ln := &singleConnListener{conn: c1, done: make(chan struct{})}
	addr := ln.Addr()
	if addr == nil {
		t.Error("Addr() returned nil")
	}
}

func TestSingleConnListener_CloseIdempotent(t *testing.T) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	ln := &singleConnListener{conn: c1, done: make(chan struct{})}
	if err := ln.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// defaultRoute
// ---------------------------------------------------------------------------

func TestDefaultRoute_Present(t *testing.T) {
	t.Helper()
	rt, _ := parseRoutes([]Route{{Backend: "http://localhost:8080"}})
	entry := rt.defaultRoute()
	if entry == nil {
		t.Fatal("defaultRoute returned nil")
	}
	if entry.backend.Host != "localhost:8080" {
		t.Errorf("backend = %s, want localhost:8080", entry.backend.Host)
	}
}

func TestDefaultRoute_Absent(t *testing.T) {
	t.Helper()
	rt, _ := parseRoutes([]Route{{Prefix: "api", Backend: "http://localhost:3001"}})
	entry := rt.defaultRoute()
	if entry != nil {
		t.Errorf("defaultRoute should be nil, got %+v", entry)
	}
}

// ---------------------------------------------------------------------------
// Certificate Rotation
// ---------------------------------------------------------------------------

func TestRotateCert(t *testing.T) {
	t.Helper()
	cert, _, err := generateSelfSignedCert("rotate-test")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cfg := newE2EETLSConfig(cert, "rotate-test")
	oldFP := cfg.Fingerprint()

	newFP, err := cfg.rotateCert()
	if err != nil {
		t.Fatalf("rotateCert: %v", err)
	}
	if newFP == "" {
		t.Fatal("new fingerprint is empty")
	}
	if newFP == oldFP {
		t.Error("fingerprint did not change after rotation")
	}
	if cfg.Fingerprint() != newFP {
		t.Errorf("Fingerprint() = %s, want %s", cfg.Fingerprint(), newFP)
	}

	// Verify the new cert is served via GetCertificate.
	got, err := cfg.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate: %v", err)
	}
	fp := sha256.Sum256(got.Certificate[0])
	if formatFingerprint(fp[:]) != newFP {
		t.Error("getCertificate returns old cert after rotation")
	}
}

func TestRotateCertFromFiles(t *testing.T) {
	t.Helper()
	cert, _, err := generateSelfSignedCert("rotate-files")
	if err != nil {
		t.Fatalf("generate initial: %v", err)
	}
	cfg := newE2EETLSConfig(cert, "rotate-files")
	oldFP := cfg.Fingerprint()

	// Generate a new cert, write to temp files, rotate.
	newCert, _, err := generateSelfSignedCert("rotate-files-new")
	if err != nil {
		t.Fatalf("generate new: %v", err)
	}
	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	keyFile := dir + "/key.pem"
	writeCertAndKeyPEM(t, newCert, certFile, keyFile)

	newFP, err := cfg.rotateCertFromFiles(certFile, keyFile)
	if err != nil {
		t.Fatalf("rotateCertFromFiles: %v", err)
	}
	if newFP == oldFP {
		t.Error("fingerprint did not change after file rotation")
	}
	if cfg.Fingerprint() != newFP {
		t.Errorf("Fingerprint() = %s, want %s", cfg.Fingerprint(), newFP)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeCertAndKeyPEM(t *testing.T, cert *tls.Certificate, certFile, keyFile string) {
	t.Helper()

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}
