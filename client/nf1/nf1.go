// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package nf1 is the transport of a capability address (nf1..., package
// capaddr): the serving side (Listener, which an agent's service table runs
// for a service served under an address) and the client (Dial, Handshake).
// The wire, after the relay's session answer (nfltr
// docs/decisions/nf1-rendezvous-2026-11-13.md section 3):
//
//  1. server -> client: the rendezvous answer frame "nf1a" | u16 len |
//     spki | u16 len | rec | u16 len | hints; the client requires
//     Address.CheckAnswer (BIND:cap.pin, BIND:cap.rendezvous);
//  2. TLS 1.3 over the session, the certificate's key pinned
//     (Address.VerifyConnection, BIND:cap.pin), no client certificate;
//  3. client -> server, its first 32 bytes inside TLS: capaddr.Proof over
//     the session's exporter (BIND:cap.secret); the server runs
//     capaddr.Admit with its own address's secret (BIND:cap.service) and
//     closes on a refusal;
//  4. server -> client inside TLS: one byte, Admitted. Then the service.
//
// A listener WithDirect signs the hints HintDirect: its sessions may move
// to a direct path, the client's first byte after the answer then picking
// a plain session, a framed one, a control exchange or a re-attach
// (client/agent direct_nf1.go; nfltr docs/decisions/nf1-direct-2026-11-14.md).
package nf1

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/nfltr/relay/client/capaddr"
)

// HintDirect is the rendezvous hints of a listener that takes direct
// paths (nfltr docs/decisions/nf1-direct-2026-11-14.md H1): the record
// signs it, so a client frames its session for them only when this
// listener said so (cap_address.pv mutant hint-unbound).
const HintDirect = "d1"

// TakesDirect reports whether checked hints (CheckAnswer accepted them)
// say the listener takes direct paths.
func TakesDirect(hints []byte) bool { return string(hints) == HintDirect }

// Admitted is the server's verdict byte once Admit accepted the proof.
const Admitted = 0x01

// answerMagic starts the rendezvous answer frame.
const answerMagic = "nf1a"

// MaxAnswer bounds the rendezvous answer frame.
const MaxAnswer = 4096

// HandshakeTimeout bounds each side's part of steps 1-4 when the caller's
// context has no deadline.
const HandshakeTimeout = 10 * time.Second

// ErrAnswer: the server's first bytes are no rendezvous answer frame.
var ErrAnswer = errors.New("nf1: no rendezvous answer")

// Listener serves one capability address: its key, certificate, signed
// record and secret. Safe for concurrent Accepts.
type Listener struct {
	addr  capaddr.Address
	key   ed25519.PrivateKey
	spki  []byte
	rec   []byte
	hints []byte
	cfg   *tls.Config
}

// Mint draws a fresh Ed25519 key and an address for it at relay (the host
// the serving agent connects to): a new capability.
func Mint(relay string) (*Listener, ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, err
	}
	addr, err := capaddr.New(relay, spki)
	if err != nil {
		return nil, nil, err
	}
	l, err := NewListener(addr, key)
	return l, key, err
}

// NewListener serves addr with key, which must match its pin.
func NewListener(addr capaddr.Address, key ed25519.PrivateKey) (*Listener, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("nf1: want an Ed25519 key")
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	if err := addr.CheckKey(spki); err != nil {
		return nil, err
	}
	rec, err := capaddr.SignRecord(key, addr.Relay, addr.RID, nil) // ponytail: no hints until direct paths serve nf1
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nf1"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates:           []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		SessionTicketsDisabled: true, // every session shows the certificate (README environment assumptions)
	}
	return &Listener{addr: addr, key: key, spki: spki, rec: rec, cfg: cfg}, nil
}

// Address is the address the listener serves.
func (l *Listener) Address() capaddr.Address { return l.addr }

// WithDirect is a copy of l whose rendezvous answer says it takes direct
// paths (HintDirect, signed): the services table makes it for a service
// with a direct mode.
func (l *Listener) WithDirect() (*Listener, error) {
	rec, err := capaddr.SignRecord(l.key, l.addr.Relay, l.addr.RID, []byte(HintDirect))
	if err != nil {
		return nil, err
	}
	c := *l
	c.rec, c.hints = rec, []byte(HintDirect)
	return &c, nil
}

// TakesDirect reports whether l's answer says it takes direct paths.
func (l *Listener) TakesDirect() bool { return TakesDirect(l.hints) }

// Certificate is the listener's certificate (the address's key), which a
// direct connection presents too (BIND:nf1direct.pin).
func (l *Listener) Certificate() tls.Certificate { return l.cfg.Certificates[0] }

// Accept runs the server's side of steps 1-4 on conn, a session the relay
// routed to this address: the TLS stream of an admitted client, or an
// error (capaddr.ErrProof for a proof under another secret) after which
// conn is closed. No byte of the service is read or written before it
// returns.
func (l *Listener) Accept(ctx context.Context, conn net.Conn) (net.Conn, error) {
	defer bound(ctx, conn)()
	tc, err := l.accept(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

func (l *Listener) accept(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if err := l.WriteAnswer(conn); err != nil {
		return nil, err
	}
	return l.Admit(ctx, conn)
}

// WriteAnswer writes the rendezvous answer frame (step 1) to conn.
func (l *Listener) WriteAnswer(conn net.Conn) error {
	_, err := conn.Write(appendAnswer(nil, l.spki, l.rec, l.hints))
	return err
}

// Admit runs steps 2-4 at the server on conn, its answer written: the TLS
// stream of an admitted client, or an error (conn is the caller's to
// close). It sets no deadline (Accept bounds it).
func (l *Listener) Admit(ctx context.Context, conn net.Conn) (*tls.Conn, error) {
	tc := tls.Server(conn, l.cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	exp, err := capaddr.Exporter(tc.ConnectionState())
	if err != nil {
		return nil, err
	}
	var proof [capaddr.ProofSize]byte
	if _, err := io.ReadFull(tc, proof[:]); err != nil {
		return nil, err
	}
	if err := capaddr.Admit(l.addr.Secret, exp, proof[:]); err != nil {
		return nil, err
	}
	if _, err := tc.Write([]byte{Admitted}); err != nil {
		return nil, err
	}
	return tc, nil
}

// Handshake runs the client's side of steps 1-4 on conn, a session the
// relay opened toward addr: the TLS stream to the admitted service, or
// capaddr.ErrPin, ErrRendezvous or ErrTLS (the server is not the address's:
// exit 7), capaddr.ErrProof (no verdict: the secret refused, exit 10),
// ErrAnswer or a connection error. conn is closed on an error.
func Handshake(ctx context.Context, conn net.Conn, addr capaddr.Address) (net.Conn, error) {
	defer bound(ctx, conn)()
	tc, err := handshake(ctx, conn, addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

func handshake(ctx context.Context, conn net.Conn, addr capaddr.Address) (net.Conn, error) {
	if _, err := ReadAnswer(conn, addr); err != nil {
		return nil, err
	}
	return ClientTLS(ctx, conn, addr)
}

// ReadAnswer reads the rendezvous answer frame (step 1) from conn and
// returns its hints once addr.CheckAnswer accepted them: ErrAnswer,
// capaddr.ErrPin or ErrRendezvous otherwise. It sets no deadline.
func ReadAnswer(conn net.Conn, addr capaddr.Address) ([]byte, error) {
	spki, rec, hints, err := readAnswer(conn)
	if err != nil {
		return nil, err
	}
	if err := addr.CheckAnswer(spki, rec, hints); err != nil {
		return nil, err
	}
	return hints, nil
}

// ClientTLS runs steps 2-4 at the client on conn, the answer read: the
// TLS stream to the admitted service, or capaddr.ErrPin, ErrTLS, ErrProof
// or a connection error (conn is the caller's to close). It sets no
// deadline.
func ClientTLS(ctx context.Context, conn net.Conn, addr capaddr.Address) (*tls.Conn, error) {
	tc := tls.Client(conn, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, // #nosec G402 -- the pin replaces the CA: VerifyConnection
		VerifyConnection:   addr.VerifyConnection,
		ServerName:         "nf1",
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		for _, e := range []error{capaddr.ErrPin, capaddr.ErrTLS} {
			if errors.Is(err, e) {
				return nil, e
			}
		}
		return nil, err
	}
	exp, err := capaddr.Exporter(tc.ConnectionState())
	if err != nil {
		return nil, err
	}
	proof := capaddr.Proof(addr.Secret, exp)
	if _, err := tc.Write(proof[:]); err != nil {
		return nil, err
	}
	var v [1]byte
	if _, err := io.ReadFull(tc, v[:]); err != nil || v[0] != Admitted {
		return nil, capaddr.ErrProof
	}
	return tc, nil
}

// bound sets conn's deadline from ctx (HandshakeTimeout without one) and
// returns the function that clears it.
func bound(ctx context.Context, conn net.Conn) func() {
	d, ok := ctx.Deadline()
	if !ok {
		d = time.Now().Add(HandshakeTimeout)
	}
	_ = conn.SetDeadline(d)
	return func() { _ = conn.SetDeadline(time.Time{}) }
}

func appendAnswer(b, spki, rec, hints []byte) []byte {
	b = append(b, answerMagic...)
	for _, f := range [][]byte{spki, rec, hints} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(f))) // #nosec G115 -- each field far below 64 KiB
		b = append(b, f...)
	}
	return b
}

func readAnswer(r io.Reader) (spki, rec, hints []byte, err error) {
	var magic [len(answerMagic)]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, nil, nil, err
	}
	if string(magic[:]) != answerMagic {
		return nil, nil, nil, ErrAnswer
	}
	total := len(answerMagic)
	var fields [3][]byte
	for i := range fields {
		var n [2]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return nil, nil, nil, err
		}
		size := int(binary.BigEndian.Uint16(n[:]))
		if total += 2 + size; total > MaxAnswer {
			return nil, nil, nil, ErrAnswer
		}
		fields[i] = make([]byte, size)
		if _, err := io.ReadFull(r, fields[i]); err != nil {
			return nil, nil, nil, err
		}
	}
	return fields[0], fields[1], fields[2], nil
}
