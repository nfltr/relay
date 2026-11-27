// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package agent — E2EE TLS termination (Phase A2).
//
// When the server routes an E2EE TLS passthrough session to this agent, the
// raw TLS bytes arrive via a ConnectTCP frame with e2ee=true.  Instead of
// dialing target_addr, the agent terminates TLS locally using its own
// certificate and forwards the decrypted traffic to the configured backend.
//
// # Certificate strategies
//
//   - WithTLSCert(certFile, keyFile) — load a user-provided certificate
//   - WithSelfSignedTLS()           — auto-generate an ECDSA P-256 self-signed cert
//
// The certificate fingerprint (SHA-256) is logged on startup so the client
// can pin it for trust-on-first-use (TOFU) verification.
package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	pb "github.com/nfltr/relay/proto/pb"
)

// e2eeTLSConfig holds the TLS configuration for E2EE termination on the
// agent side.  It is separate from Config.TLSConfig which is used for the
// gRPC connection to the server.
//
// The certificate is served via GetCertificate callback so it can be
// atomically rotated at runtime without disconnecting the agent.
type e2eeTLSConfig struct {
	mu          sync.RWMutex
	cert        *tls.Certificate
	fingerprint string // SHA-256 hex fingerprint of the leaf certificate
	tlsConfig   *tls.Config
	agentID     string // stored for self-signed rotation

	// onRotate is called after a successful certificate rotation with
	// the new fingerprint.  Set by runTCPTunnel to send a control frame.
	onRotate func(newFingerprint string)

	// wrapHTTP, when set, wraps the handler of every E2EE request: a
	// feature that reads requests (E2EESetup.RequireBasicAuth,
	// RequireSharePolicy). Sessions then take the HTTP path instead of the
	// stream path (serveE2EE).
	wrapHTTP func(http.Handler) http.Handler

	// rewriteHost sends the backend its own host as Host
	// (E2EESetup.RewriteHost); else it gets the host the client asked for.
	rewriteHost bool

	// shareCodes are the shares whose policy wrapHTTP enforces; the agent
	// names them on its ConnectTCP streams (sharePolicyHeader).
	shareCodes []string
}

// addWrap adds wrap around the request handler; every wrap added applies.
func (c *e2eeTLSConfig) addWrap(wrap func(http.Handler) http.Handler) {
	c.wrapHTTP = composeWraps(c.wrapHTTP, wrap)
}

// generateSelfSignedCert creates an ECDSA P-256 self-signed certificate valid
// for 1 year.  The certificate includes the agentID as both the CN and a DNS
// SAN so that TLS clients sending SNI matching the agent ID will accept it.
func generateSelfSignedCert(agentID string) (*tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    now.Add(-5 * time.Minute), // clock skew tolerance
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{agentID},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, "", fmt.Errorf("create certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	// Compute SHA-256 fingerprint of the DER-encoded certificate.
	fp := sha256.Sum256(certDER)
	fingerprint := formatFingerprint(fp[:])

	return tlsCert, fingerprint, nil
}

// formatFingerprint formats raw hash bytes as a colon-separated hex string.
func formatFingerprint(hash []byte) string {
	hex := strings.ToUpper(hex.EncodeToString(hash))
	parts := make([]string, 0, len(hash))
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":")
}

// loadCertFromFiles loads a TLS certificate from PEM-encoded files and
// computes its SHA-256 fingerprint.
func loadCertFromFiles(certFile, keyFile string) (*tls.Certificate, string, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, "", fmt.Errorf("load certificate: %w", err)
	}

	if len(cert.Certificate) == 0 {
		return nil, "", fmt.Errorf("certificate file contains no certificates")
	}

	fp := sha256.Sum256(cert.Certificate[0])
	fingerprint := formatFingerprint(fp[:])

	return &cert, fingerprint, nil
}

// newE2EETLSConfig builds the tls.Config used to terminate E2EE connections
// on the agent.  It configures TLS 1.2+ with only forward-secret cipher
// suites (ECDHE) and returns the leaf certificate fingerprint.
// TLS 1.3 cipher suites all provide forward secrecy and are managed by Go
// automatically; these CipherSuites only apply to TLS 1.2 negotiation.
//
// The certificate is served via GetCertificate so it can be rotated at
// runtime without disconnecting.
func newE2EETLSConfig(cert *tls.Certificate, agentID string) *e2eeTLSConfig {
	fp := sha256.Sum256(cert.Certificate[0])

	cfg := &e2eeTLSConfig{
		cert:        cert,
		fingerprint: formatFingerprint(fp[:]),
		agentID:     agentID,
	}

	cfg.tlsConfig = &tls.Config{
		GetCertificate: cfg.getCertificate,
		MinVersion:     tls.VersionTLS12,
		CipherSuites: []uint16{
			// TLS 1.2 ECDHE suites — all provide forward secrecy.
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		// CurvePreferences is left to Go's defaults, which put the hybrid
		// post-quantum X25519MLKEM768 first (TestE2EETLSNegotiatesPostQuantum).
	}

	return cfg
}

// getCertificate returns the current certificate for TLS handshakes.
// Called by crypto/tls for each incoming connection, enabling rotation.
func (c *e2eeTLSConfig) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert, nil
}

// Fingerprint returns the SHA-256 fingerprint of the current certificate.
func (c *e2eeTLSConfig) Fingerprint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.fingerprint
}

// rotateCert generates a new self-signed certificate and atomically swaps
// it in.  New TLS connections will use the new cert; existing connections
// are unaffected.  Returns the new fingerprint.
func (c *e2eeTLSConfig) rotateCert() (string, error) {
	cert, fp, err := generateSelfSignedCert(c.agentID)
	if err != nil {
		return "", fmt.Errorf("rotate cert: %w", err)
	}
	c.mu.Lock()
	c.cert = cert
	c.fingerprint = fp
	cb := c.onRotate
	c.mu.Unlock()
	if cb != nil {
		cb(fp)
	}
	return fp, nil
}

// rotateCertFromFiles loads a new certificate from PEM files and atomically
// swaps it in.  Returns the new fingerprint.
func (c *e2eeTLSConfig) rotateCertFromFiles(certFile, keyFile string) (string, error) {
	cert, fp, err := loadCertFromFiles(certFile, keyFile)
	if err != nil {
		return "", fmt.Errorf("rotate cert from files: %w", err)
	}
	c.mu.Lock()
	c.cert = cert
	c.fingerprint = fp
	cb := c.onRotate
	c.mu.Unlock()
	if cb != nil {
		cb(fp)
	}
	return fp, nil
}

// fingerprintControlSessionID is the session_id used for control frames
// that notify the server of a rotated TLS certificate fingerprint.
const fingerprintControlSessionID = "_fingerprint"

// E2EESetup holds E2EE TLS state for CLI commands that use the legacy gRPC
// path instead of the agent SDK.  Create via [NewE2EESetup].
type E2EESetup struct {
	cfg *e2eeTLSConfig
}

// NewE2EESetup prepares E2EE TLS termination.  If certFile and keyFile are
// both non-empty, the certificate is loaded from those files; otherwise a
// self-signed ECDSA P-256 certificate is generated for agentID.
// The fingerprint is logged for client-side TOFU pin verification.
func NewE2EESetup(agentID, certFile, keyFile string, logger *slog.Logger) (*E2EESetup, error) {
	var (
		cert *tls.Certificate
		fp   string
		err  error
	)
	if certFile != "" && keyFile != "" {
		cert, fp, err = loadCertFromFiles(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		logger.Info("e2ee: loaded TLS certificate", "fingerprint", fp, "cert", certFile)
	} else {
		cert, fp, err = generateSelfSignedCert(agentID)
		if err != nil {
			return nil, err
		}
		logger.Info("e2ee: generated self-signed TLS certificate", "fingerprint", fp, "agent_id", agentID)
	}
	return &E2EESetup{cfg: newE2EETLSConfig(cert, agentID)}, nil
}

// Fingerprint returns the SHA-256 fingerprint of the E2EE certificate.
// Fingerprint returns the SHA-256 fingerprint of the E2EE certificate.
// RewriteHost sends the backend its own host (the backend URL's) as the Host
// of every E2EE request instead of the host the client asked for
// (Config.RewriteHost). Call it before RunTCPTunnel.
func (s *E2EESetup) RewriteHost() { s.cfg.rewriteHost = true }

func (s *E2EESetup) Fingerprint() string { return s.cfg.Fingerprint() }

// RunTCPTunnel opens a ConnectTCP gRPC stream and serves E2EE TLS sessions.
// It blocks until ctx is cancelled or the stream ends. dial is as for the
// package's RunTCPTunnel.
func (s *E2EESetup) RunTCPTunnel(ctx context.Context, client pb.DispatcherClient, dial RelayDialer, streamCtx context.Context, forwardAddr, defaultBackend string, logger *slog.Logger) error {
	return runTCPTunnel(ctx, client, dial, streamCtx, sessionTargets{forwardAddr: forwardAddr, defaultBackend: defaultBackend}, s.cfg, logger, nil)
}
