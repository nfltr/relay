// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/crypto/acme/autocert"
)

// ACMEConfig configures automatic certificate management via ACME (Let's
// Encrypt) for the agent's E2EE TLS termination.
//
// When an agent has a stable DNS name (e.g. myapp.tunnel.example.com),
// ACME eliminates the need for TOFU fingerprint pinning — clients trust
// the certificate through the normal public CA chain.
type ACMEConfig struct {
	// Domains is the list of domain names to obtain certificates for.
	// At least one domain is required.
	Domains []string

	// CacheDir is the path for storing obtained certificates.
	// If empty, defaults to a subdirectory of the user's cache dir.
	CacheDir string

	// Email is an optional contact address for the ACME account.
	// Let's Encrypt sends expiration warnings to this address.
	Email string
}

// WithACME configures the agent to obtain E2EE TLS certificates
// automatically from Let's Encrypt via the ACME TLS-ALPN-01 challenge.
//
// Requirements:
//   - The agent must be reachable on port 443 from the internet (for the
//     ACME challenge to succeed).
//   - dns must resolve to the agent's public IP.
//
// The certificate is auto-renewed before expiration.  The fingerprint
// changes on each renewal and is sent to the server via the
// _fingerprint control frame.
func WithACME(cfg ACMEConfig) Option {
	return func(a *agent) {
		if len(cfg.Domains) == 0 {
			panic("agent.WithACME: at least one domain is required")
		}
		acmeCfg, err := newACMEE2EEConfig(cfg, a.cfg.AgentID, a.logger)
		if err != nil {
			panic("agent.WithACME: " + err.Error())
		}
		a.e2eeTLS = acmeCfg
	}
}

// newACMEE2EEConfig creates an e2eeTLSConfig backed by an autocert.Manager.
// The manager handles certificate issuance and renewal automatically.
func newACMEE2EEConfig(cfg ACMEConfig, agentID string, logger *slog.Logger) (*e2eeTLSConfig, error) {
	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		home, err := os.UserCacheDir()
		if err != nil {
			home = "/tmp"
		}
		cacheDir = home + "/nfltr/acme"
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create ACME cache dir %s: %w", cacheDir, err)
	}

	manager := &autocert.Manager{
		Cache:      autocert.DirCache(cacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
		Email:      cfg.Email,
	}

	logger.Info("e2ee: ACME enabled — certificates obtained from Let's Encrypt",
		"domains", cfg.Domains, "cache", cacheDir)

	acmeTLS := manager.TLSConfig()
	acmeTLS.MinVersion = tls.VersionTLS12
	acmeTLS.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	// CurvePreferences stays Go's default: hybrid post-quantum X25519MLKEM768
	// first (TestE2EETLSNegotiatesPostQuantum).

	// Wrap the ACME GetCertificate to track fingerprint updates.
	acmeGetCert := acmeTLS.GetCertificate

	e := &e2eeTLSConfig{
		agentID:     agentID,
		fingerprint: "ACME:pending", // updated on first handshake
	}

	acmeTLS.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := acmeGetCert(hello)
		if err != nil {
			return nil, err
		}
		// Update cached fingerprint if the cert changed (renewal).
		if len(cert.Certificate) > 0 {
			fp := sha256.Sum256(cert.Certificate[0])
			newFP := formatFingerprint(fp[:])

			e.mu.Lock()
			oldFP := e.fingerprint
			if newFP != oldFP {
				e.cert = cert
				e.fingerprint = newFP
				cb := e.onRotate
				e.mu.Unlock()
				if cb != nil {
					cb(newFP)
				}
				logger.Info("e2ee: ACME certificate updated", "fingerprint", newFP)
			} else {
				e.mu.Unlock()
			}
		}
		return cert, nil
	}

	e.tlsConfig = acmeTLS

	return e, nil
}

// NewACMEE2EESetup creates an E2EESetup backed by ACME for CLI commands.
func NewACMEE2EESetup(agentID string, domains []string, cacheDir, email string, logger *slog.Logger) (*E2EESetup, error) {
	cfg := ACMEConfig{
		Domains:  domains,
		CacheDir: cacheDir,
		Email:    email,
	}
	e2eeCfg, err := newACMEE2EEConfig(cfg, agentID, logger)
	if err != nil {
		return nil, err
	}
	return &E2EESetup{cfg: e2eeCfg}, nil
}
