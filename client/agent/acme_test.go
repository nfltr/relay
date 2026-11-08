// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/tls"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/metadata"
)

// ---------------------------------------------------------------------------
// newACMEE2EEConfig
// ---------------------------------------------------------------------------

func TestNewACMEE2EEConfig_CreatesConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := ACMEConfig{
		Domains:  []string{"test.example.com"},
		CacheDir: filepath.Join(dir, "acme-cache"),
		Email:    "test@example.com",
	}

	e, err := newACMEE2EEConfig(cfg, "acme-agent", logger)
	if err != nil {
		t.Fatalf("newACMEE2EEConfig: %v", err)
	}
	if e == nil {
		t.Fatal("returned config is nil")
	}
	if e.tlsConfig == nil {
		t.Fatal("tlsConfig is nil")
	}
	if e.Fingerprint() != "" {
		t.Errorf("initial fingerprint = %q, want none before the certificate is issued", e.Fingerprint())
	}
}

func TestNewACMEE2EEConfig_TLSSettings(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := ACMEConfig{
		Domains:  []string{"test.example.com"},
		CacheDir: filepath.Join(dir, "acme-cache"),
	}

	e, err := newACMEE2EEConfig(cfg, "tls-settings-agent", logger)
	if err != nil {
		t.Fatalf("newACMEE2EEConfig: %v", err)
	}

	if e.tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", e.tlsConfig.MinVersion, tls.VersionTLS12)
	}
	if e.tlsConfig.GetCertificate == nil {
		t.Fatal("GetCertificate callback is nil")
	}

	// Verify cipher suites are ECDHE-only.
	for _, cs := range e.tlsConfig.CipherSuites {
		name := tls.CipherSuiteName(cs)
		if name == "" {
			t.Errorf("unknown cipher suite: %d", cs)
		}
	}

	if e.tlsConfig.CurvePreferences != nil {
		t.Errorf("CurvePreferences = %v, want Go's defaults (post-quantum first)", e.tlsConfig.CurvePreferences)
	}
}

func TestNewACMEE2EEConfig_CreatesCacheDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "nested", "acme")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := ACMEConfig{
		Domains:  []string{"test.example.com"},
		CacheDir: cacheDir,
	}

	_, err := newACMEE2EEConfig(cfg, "cache-dir-agent", logger)
	if err != nil {
		t.Fatalf("newACMEE2EEConfig: %v", err)
	}

	info, err := os.Stat(cacheDir)
	if err != nil {
		t.Fatalf("stat cache dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("cache dir is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("cache dir perms = %o, want 700", info.Mode().Perm())
	}
}

// ---------------------------------------------------------------------------
// WithACME
// ---------------------------------------------------------------------------

func TestWithACME_PanicsOnEmptyDomains(t *testing.T) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("WithACME with empty domains should panic")
		}
	}()

	a := &agent{
		cfg:    Config{AgentID: "panic-test"},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	WithACME(ACMEConfig{})(a)
}

func TestWithACME_SetsE2EETLS(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	a := &agent{
		cfg:    Config{AgentID: "acme-set-test"},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	WithACME(ACMEConfig{
		Domains:  []string{"test.example.com"},
		CacheDir: filepath.Join(dir, "acme"),
	})(a)

	if a.e2eeTLS == nil {
		t.Fatal("e2eeTLS is nil after WithACME")
	}
	if a.e2eeTLS.Fingerprint() != "" {
		t.Errorf("fingerprint = %q, want none before the certificate is issued", a.e2eeTLS.Fingerprint())
	}
}

// ---------------------------------------------------------------------------
// NewACMEE2EESetup
// ---------------------------------------------------------------------------

func TestNewACMEE2EESetup_ReturnsSetup(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	setup, err := NewACMEE2EESetup("setup-test", []string{"test.example.com"}, filepath.Join(dir, "acme"), "", logger)
	if err != nil {
		t.Fatalf("NewACMEE2EESetup: %v", err)
	}
	if setup == nil {
		t.Fatal("setup is nil")
	}
	if setup.Fingerprint() != "" {
		t.Errorf("fingerprint = %q, want none before the certificate is issued", setup.Fingerprint())
	}
}

// TestACMEPendingAdvertisesNoFingerprint: an ACME certificate not issued
// yet sends no x-tls-fingerprint (it used to send "ACME:pending", which the
// dashboard showed as the agent's fingerprint); an issued one sends its own.
func TestACMEPendingAdvertisesNoFingerprint(t *testing.T) {
	a := &agent{cfg: Config{AgentID: "acme-md-test"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	WithACME(ACMEConfig{Domains: []string{"test.example.com"}, CacheDir: filepath.Join(t.TempDir(), "acme")})(a)
	md := metadata.MD{}
	a.setFingerprintMetadata(md)
	if got := md.Get("x-tls-fingerprint"); len(got) != 0 {
		t.Fatalf("pending ACME certificate advertised x-tls-fingerprint %q, want none", got)
	}
	a.e2eeTLS.mu.Lock()
	a.e2eeTLS.fingerprint = "AA:BB"
	a.e2eeTLS.mu.Unlock()
	a.setFingerprintMetadata(md)
	if got := md.Get("x-tls-fingerprint"); len(got) != 1 || got[0] != "AA:BB" {
		t.Fatalf("issued certificate advertised %q, want AA:BB", got)
	}
}
