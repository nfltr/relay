// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package machinecred presents a machine's certificate to the relay
// (client/machinecert holds the key, the certificate and the files
// `nfltr config login` saves). Every program that talks to the relay as
// this machine (nfltr's CLI and agents, nfltr-send, your own) reads them
// through Credential: ForRelay loads the pair once per process and
// directory, Credential.Run renews it in place with machinecert.Loop (each
// new connection presents the newest; a renewal never writes over a pair
// `nfltr config login` put in the directory since), and the credential is
// presented on gRPC (RelayTLS, TLSConfig) and on HTTP (Transport,
// HTTPClient). The relay authenticates the machine from the certificate
// alone; a refused certificate ends the command with ErrRefused
// (Credential.Refusal). Machines resolves a machine name of the caller's
// account to its id (GET /api/v1/machines/resolve).
package machinecred

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nfltr/relay/client/machinecert"
	"github.com/nfltr/relay/client/relayoutage"
	"github.com/nfltr/relay/client/relaytrust"
	relayv1 "github.com/nfltr/relay/proto/nfltr/relay/v1"
	"github.com/nfltr/relay/proto/wire/dataplane"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Credential is the machine certificate a process presents to the relay
// as its TLS client certificate, instead of an API key: a machine that
// holds one for the relay presents only it (chosen once at start, never
// switched to the key at run time: a fallback would let a revoked machine
// keep working on its key). Run renews it in place (at 2/3 of its
// lifetime, +-10 %: machinecert.Loop), so each new connection presents the
// newest. A refused certificate (revoked, rotated away, expired) ends the
// command with ErrRefused. No new state machine: renewal is
// machinecert.Loop (relay-server spec/MachineAuth.tla Renew).
type Credential struct {
	key      *ecdsa.PrivateKey
	dir      string
	host, id string             // the relay's host and the machine: never change
	name     string             // the machine's name in its account, as loaded
	s        *machinecert.Saved // the certificate as last saved; Run's goroutine only
	cur      atomic.Pointer[tls.Certificate]
	refused  atomic.Bool // the renewal was refused for good
	running  atomic.Bool // Run started the renewal
	once     sync.Once
}

// ErrRefused ends a command whose machine certificate the relay refused;
// the API key is never tried instead.
var ErrRefused = errors.New("the relay refused this machine's certificate (revoked, rotated away or expired): run `nfltr config login` to enrol this machine again")

// Refusal is err as the command's error: ErrRefused (err kept) when err is
// the relay's typed refusal of the credential (gRPC Unauthenticated, or
// PermissionDenied typed UNAUTHENTICATED; HTTP 401 or 403) or the renewal
// was refused for good;
// else err (a network error, retried with the same certificate).
func (c *Credential) Refusal(err error) error {
	if err == nil || errors.Is(err, ErrRefused) {
		return err
	}
	if c.refused.Load() || refusedByRelay(err) {
		return fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return err
}

func refusedByRelay(err error) bool {
	if nu, ok := errors.AsType[*dataplane.NoUpgradeError](err); ok {
		return nu.Status == http.StatusUnauthorized || nu.Status == http.StatusForbidden
	}
	// Unauthenticated, or PermissionDenied typed UNAUTHENTICATED (no
	// credential reached the relay): another PermissionDenied is the
	// relay's policy, such as an agent name this credential may not use
	// (relay-core grpcauth), never a refused certificate (pubcheck
	// 2026-11-18 showed one as "revoked").
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch s.Code() {
	case codes.Unauthenticated:
		return true
	case codes.PermissionDenied:
		for _, d := range s.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == relayv1.ErrorReason_ERROR_REASON_UNAUTHENTICATED.String() {
				return true
			}
		}
	}
	return false
}

// ponytail: one credential per process and directory (one renewal loop for
// the machine, whatever number of agents a process runs); Forget resets it.
var (
	credsMu sync.Mutex
	creds   = map[string]*Credential{}
)

// Forget drops the credentials loaded so far (the next ForRelay reads
// the files again).
func Forget() {
	credsMu.Lock()
	defer credsMu.Unlock()
	clear(creds)
}

// ForRelay is the credential dir holds for the relay at server (its gRPC
// address, HTTP address or URL); nil when dir holds no certificate or one
// for another relay. An expired one is still the credential: the relay
// refuses it (ErrRefused: enrol again).
func ForRelay(dir, server string) *Credential {
	credsMu.Lock()
	defer credsMu.Unlock()
	c, ok := creds[machinecert.CertPath(dir)]
	if !ok {
		c = load(dir)
		creds[machinecert.CertPath(dir)] = c
	}
	if c == nil || !sameRelay(c.host, server) {
		return nil
	}
	return c
}

// For is the credential an agent dialing server presents: nil when it
// gives its own certificate files (mTLS), dials in plaintext, or dir
// holds no certificate for server.
func For(dir, server string, useTLS, ownCert bool) *Credential {
	if ownCert || !useTLS {
		return nil
	}
	return ForRelay(dir, server)
}

// sameRelay: server (a gRPC address, an HTTP address or URL) is the relay
// whose host is host; a hosted relay's gRPC host is its HTTP host with
// "grpc." in front (proxyurl.RelayHTTPAddr). host may carry a port: the
// relay's `enrol-code --dir --relay` writes the gRPC host:port it names.
func sameRelay(host, server string) bool {
	return strings.TrimPrefix(machinecert.RelayHost(host), "grpc.") == strings.TrimPrefix(machinecert.RelayHost(server), "grpc.")
}

func load(dir string) *Credential {
	s, err := machinecert.Load(dir)
	if err != nil {
		return nil
	}
	key, err := loadKey(dir)
	if err != nil {
		return nil
	}
	c := &Credential{key: key, dir: dir, host: s.RelayHost, id: s.MachineID, name: s.Name, s: s}
	t := s.TLS(key)
	c.cur.Store(&t)
	return c
}

// loadKey is $NFLTR_MACHINE_KEY when set, else dir's machine.key.
func loadKey(dir string) (*ecdsa.PrivateKey, error) {
	v := os.Getenv(machinecert.KeyEnv)
	if v == "" {
		return machinecert.LoadKey(machinecert.KeyPath(dir))
	}
	blk, _ := pem.Decode([]byte(v))
	if blk == nil {
		return nil, errors.New(machinecert.KeyEnv + ": not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", machinecert.KeyEnv, err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New(machinecert.KeyEnv + ": not an ECDSA key")
	}
	return ek, nil
}

// KeyPEM is the machine key as machinecert.KeyEnv carries it: what a node hands the
// agent processes it launches.
func (c *Credential) KeyPEM() string {
	der, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// MachineID is the machine the certificate names.
func (c *Credential) MachineID() string { return c.id }

// Name is the machine's name in its account as the certificate was saved
// ("" when it has none).
func (c *Credential) Name() string { return c.name }

// RelayTLS is the relay TLS configuration presenting the certificate (the
// relay's pin, as the SDK's own configuration has it).
func (c *Credential) RelayTLS(skipVerify bool) *tls.Config {
	base := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, InsecureSkipVerify: skipVerify} // #nosec G402 -- --skip-verify is the operator's choice
	return c.TLSConfig(relaytrust.WithPin(base, os.Getenv(relaytrust.PinEnv)))
}

// TLSConfig is base (cloned) presenting the certificate: the newest at
// each handshake.
func (c *Credential) TLSConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return c.cur.Load(), nil
	}
	return cfg
}

// HTTP/2 health checks on the relay's HTTP calls, as mailboxclient's own
// default client has them (a long-poll's answer crosses a NAT that lost
// the connection's mapping; mailboxclient/health.go, guard
// TestLongPollAnswerCrossesALostNATMapping there).
const (
	pingAfter   = 5 * time.Second
	pingTimeout = 10 * time.Second
)

// Transport is Go's default transport as this process configured it (a
// relay pin: relaytrust.Install) presenting the certificate on every
// connection to the relay's HTTP side (REST, mailboxes, blobs, the Fleet
// API), with HTTP/2 health checks. The relay authenticates it as the
// machine, as on gRPC.
func (c *Credential) Transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = c.TLSConfig(t.TLSClientConfig)
	h2 := http.HTTP2Config{}
	if t.HTTP2 != nil {
		h2 = *t.HTTP2
	}
	h2.SendPingTimeout, h2.PingTimeout = pingAfter, pingTimeout
	t.HTTP2 = &h2
	return t
}

// HTTPClient is a client over Transport, bounded only by each call's
// context.
func (c *Credential) HTTPClient() *http.Client { return &http.Client{Transport: c.Transport()} }

// Run renews the certificate until ctx ends, once per process (later
// calls return at once). After a final refusal or an expiry the
// certificate is still presented, the relay refuses it and the command
// ends with ErrRefused (Refusal).
func (c *Credential) Run(ctx context.Context, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	c.once.Do(func() {
		c.running.Store(true)
		go c.renew(ctx, logger)
	})
}

// Renewing: Run started renewing the certificate in this process.
func (c *Credential) Renewing() bool { return c.running.Load() }

// RenewHTTP is the client renewals use.
func RenewHTTP() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: relayoutage.Throttled(nil)}
}

func (c *Credential) renew(ctx context.Context, logger *slog.Logger) {
	client := &machinecert.Client{BaseURL: c.s.BaseURL, HTTP: RenewHTTP()}
	loop := machinecert.Loop{
		Renew: func(ctx context.Context, cur *machinecert.Cert) (*machinecert.Cert, error) {
			next, err := client.Renew(ctx, cur, c.key)
			if err != nil { // each attempt, hours ahead of the expiry (guard TestRenewalFailureIsLoggedWithTheTimeLeft)
				logger.Warn("machine certificate renewal failed", "machine", c.id, "error", err, "expires_in", time.Until(cur.NotAfter).Truncate(time.Second), "not_after", cur.NotAfter)
			}
			return next, err
		},
		Save: func(next *machinecert.Cert) error { return c.save(next, logger) },
	}
	if err := loop.Run(ctx, &c.s.Cert); err != nil && ctx.Err() == nil {
		c.refused.Store(true)
		logger.Error("machine certificate not renewed", "error", c.Refusal(err))
	}
}

// save presents next from now on and writes it to the directory, only
// while the directory still holds this process's pair: after
// `nfltr config login` put another machine's key or certificate there, a
// long-running process renewing its own certificate must not write it over
// the new pair (the certificate on disk would no longer match the key, and
// every process of the machine would fail its handshake). Then the renewal
// is kept in memory only, and logged.
// ponytail: check then rename, not a lock; login racing a renewal within
// that window is the residue.
func (c *Credential) save(next *machinecert.Cert, logger *slog.Logger) error {
	s := *c.s
	s.Cert = *next
	if err := c.ownsDir(); err != nil {
		logger.Error("machine certificate renewed in memory only: the config directory now holds another machine's credential", "machine", next.MachineID, "dir", c.dir, "err", err)
	} else if err := s.Store(c.dir); err != nil {
		return err
	}
	c.s = &s
	t := next.TLS(c.key)
	c.cur.Store(&t)
	logger.Info("machine certificate renewed", "machine", next.MachineID, "not_after", next.NotAfter)
	return nil
}

// ownsDir: the directory's key (when this process loaded it from there,
// not machinecert.KeyEnv) and its certificate are still this process's key's.
func (c *Credential) ownsDir() error {
	if os.Getenv(machinecert.KeyEnv) == "" {
		k, err := machinecert.LoadKey(machinecert.KeyPath(c.dir))
		if err != nil {
			return err
		}
		if !k.Equal(c.key) {
			return errors.New(machinecert.KeyPath(c.dir) + " is another key")
		}
	}
	s, err := machinecert.Load(c.dir)
	if err != nil {
		return err
	}
	if pub, ok := s.Leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&c.key.PublicKey) {
		return errors.New(machinecert.CertPath(c.dir) + " is another machine's certificate (" + s.MachineID + ")")
	}
	return nil
}
