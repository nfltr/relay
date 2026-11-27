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
// a session (a TLS record), a control exchange or a re-attach (client/agent
// direct_nf1.go; nfltr docs/decisions/nf1-direct-2026-11-14.md,
// direct-once-2026-11-22.md). Such a session is framed inside its TLS
// (relay spec/proverif/direct_once.pv epoch 0): its client offers ALPN
// ALPNFramed and requires it negotiated, so the kind is in the TLS
// transcript, never a byte the relay can change (BIND:once.plain). "d1"
// was the hint of the layering before (pathswitch under the session's
// TLS): an answer that signs it takes no direct path here, and a "d1"
// client sees none in a "d2" answer, so an older end and a newer one meet
// relayed (2026-11-22).
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
	"strings"
	"time"

	"github.com/nfltr/relay/client/capaddr"
)

// HintDirect is the rendezvous hints of a listener that takes direct
// paths (nfltr docs/decisions/nf1-direct-2026-11-14.md H1): the record
// signs it, so a client frames its session for them only when this
// listener said so (cap_address.pv mutant hint-unbound).
const HintDirect = "d2"

// HintDatagram is the rendezvous hints' flag of a datagram service (kind
// udp; nfltr docs/decisions/nf1-udp-2026-11-14.md section 3): the record
// signs it, so a relay cannot make a stream client speak to a datagram
// service or the reverse (BIND:cap.kind).
const HintDatagram = "u1"

// HintAnonymous is the rendezvous hints' flag of a listener served with
// no account (nfltr docs/decisions/nf1-anon-2026-11-16.md section 2): its
// relay carries signalling only, so a client sends no byte of the service
// until the session is on a direct path and never re-attaches it relayed
// (ErrDirectRequired otherwise). Signed by the record: a relay that strips
// it breaks the record (exit 7).
const HintAnonymous = "a1"

// HintBrowser is the rendezvous hints' flag of a listener whose agent
// takes browser visitors' data channels (nfltr
// docs/decisions/browser-peer-2026-11-16.md section 5): the record signs
// it, so a page tries the direct path only when the agent said so; after
// the answer the page's first byte picks a control session (client/agent
// direct_nf1.go).
const HintBrowser = "b1"

// Hints are a comma-separated list of flags ("d2", "u1", "a1", "b1", "d2,b1"),
// signed by the record.
func hasHint(hints []byte, h string) bool {
	for f := range strings.SplitSeq(string(hints), ",") {
		if f == h {
			return true
		}
	}
	return false
}

// TakesDirect reports whether checked hints (CheckAnswer accepted them)
// say the listener takes direct paths.
func TakesDirect(hints []byte) bool { return hasHint(hints, HintDirect) }

// Anonymous reports whether checked hints say the listener is served
// with no account (HintAnonymous).
func Anonymous(hints []byte) bool { return hasHint(hints, HintAnonymous) }

// ErrDirectRequired: the address is served with no account and its
// session found no direct path (or lost it): relaying needs the serving
// side's account (relay ERROR_REASON_ACCOUNT_REQUIRED, exit 12).
var ErrDirectRequired = errors.New("nf1: no direct path formed, and this address has no account behind it: relaying needs the serving side's nfltr account")

// ErrKind: the address serves the other kind (a datagram service to a
// stream dial, or the reverse), as its signed record says.
var ErrKind = errors.New("nf1: the address serves another kind than dialled (stream or datagram)")

// CheckKind is the client's check of checked hints against its dial:
// datagram for a datagram dial (BIND:cap.kind).
func CheckKind(hints []byte, datagram bool) error {
	if hasHint(hints, HintDatagram) != datagram {
		return ErrKind
	}
	return nil
}

// Dial's errors for the relay's answers (in every build: a browser's
// transport answers with the same refusals), each one exit code of the connect
// sidecar's table (the decision's section 6); a server that is not the
// address's is capaddr.ErrPin, ErrRendezvous or ErrTLS (7), a refused
// secret capaddr.ErrProof (10).
var (
	// ErrNotServed: no live agent serves the address at its relay (unknown,
	// offline, or the relay serves no nf1 addresses): exit 3.
	ErrNotServed = errors.New("nf1: no service at this address")
	// ErrRefused: the relay refused the open (a cap, its E2EE policy): exit 4.
	ErrRefused = errors.New("nf1: the relay refused the session")
	// ErrUnreachable: the relay was not reached or ended the connection: exit 5.
	ErrUnreachable = errors.New("nf1: relay unreachable")
	// ErrBalance: the serving account's balance is exhausted: exit 9.
	ErrBalance = errors.New("nf1: the serving account's balance is exhausted")
)

// Admitted is the server's verdict byte once Admit accepted the proof.
const Admitted = 0x01

// A session's kind (AdmitKind): plain, or framed for direct paths (its
// TLS negotiated ALPNFramed).
const (
	KindPlain  = 'P' // the service's bytes follow
	KindFramed = 'F' // link pathswitch frames follow, inside this TLS
)

// ALPNFramed is the ALPN of a session framed for direct paths: the
// client offers it (ClientTLSFramed), a listener that takes direct paths
// selects it (AdmitKind); a plain session offers none.
const ALPNFramed = "nf1-framed"

// answerMagic starts the rendezvous answer frame.
const answerMagic = "nf1a"

// MaxAnswer bounds the rendezvous answer frame.
const MaxAnswer = 4096

// HandshakeTimeout bounds each side's part of steps 1-4 when the caller's
// context has no deadline.
const HandshakeTimeout = 10 * time.Second

// ErrAnswer: the server's first bytes are no rendezvous answer frame.
var ErrAnswer = errors.New("nf1: no rendezvous answer")

// ErrKindRefused: the session's kind is not one the other end serves (a
// framed session to a listener without direct paths: no ALPNFramed).
var ErrKindRefused = errors.New("nf1: session kind refused")

// Listener serves one capability address: its key, certificate, signed
// record and secret. Safe for concurrent Accepts.
type Listener struct {
	addr   capaddr.Address
	key    ed25519.PrivateKey
	spki   []byte
	rec    []byte
	hints  []byte
	reg    []byte // capaddr.RegistrationProof; nil for an address minted before rids were bound to keys
	cfg    *tls.Config
	framed *tls.Config // cfg selecting ALPNFramed (AdmitKind)
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
	reg, err := capaddr.RegistrationProof(key, addr)
	if err != nil && !errors.Is(err, capaddr.ErrRegister) {
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
	framed := cfg.Clone()
	framed.NextProtos = []string{ALPNFramed}
	return &Listener{addr: addr, key: key, spki: spki, rec: rec, reg: reg, cfg: cfg, framed: framed}, nil
}

// Address is the address the listener serves.
func (l *Listener) Address() capaddr.Address { return l.addr }

// RegistrationProof is what the agent sends its relay with the
// declaration of the address's rid (agentservices.RegHeader), or nil for
// an address whose rid is not bound to its key (minted before rids were:
// a relay that requires the proof refuses it; serve a new address).
func (l *Listener) RegistrationProof() []byte { return l.reg }

// WithDirect is a copy of l whose rendezvous answer says it takes direct
// paths (HintDirect, signed): the services table makes it for a service
// with a direct mode.
func (l *Listener) WithDirect() (*Listener, error) { return l.withHint(HintDirect) }

// WithDatagram is a copy of l whose rendezvous answer says it serves
// datagrams (HintDatagram, signed): the services table makes it for a udp
// service.
func (l *Listener) WithDatagram() (*Listener, error) { return l.withHint(HintDatagram) }

// WithAnonymous is a copy of l whose rendezvous answer says it is served
// with no account (HintAnonymous, signed): nfnet.Listen makes it for an
// address served with no credential.
func (l *Listener) WithAnonymous() (*Listener, error) { return l.withHint(HintAnonymous) }

// WithBrowser is a copy of l whose rendezvous answer says it takes
// browser visitors' data channels (HintBrowser, signed): the services table
// makes it for a service with Service.BrowserDirect.
func (l *Listener) WithBrowser() (*Listener, error) { return l.withHint(HintBrowser) }

// TakesBrowser reports whether checked hints (CheckAnswer accepted them)
// say the agent takes browser visitors' data channels.
func TakesBrowser(hints []byte) bool { return hasHint(hints, HintBrowser) }

// TakesBrowser reports whether l's answer says it takes browser visitors'
// data channels.
func (l *Listener) TakesBrowser() bool { return TakesBrowser(l.hints) }

// withHint adds flag h to l's signed hints, in the order d2, u1, a1, b1.
func (l *Listener) withHint(h string) (*Listener, error) {
	var flags []string
	for _, f := range []string{HintDirect, HintDatagram, HintAnonymous, HintBrowser} {
		if f == h || hasHint(l.hints, f) {
			flags = append(flags, f)
		}
	}
	hints := []byte(strings.Join(flags, ","))
	rec, err := capaddr.SignRecord(l.key, l.addr.Relay, l.addr.RID, hints)
	if err != nil {
		return nil, err
	}
	c := *l
	c.rec, c.hints = rec, hints
	return &c, nil
}

// Datagram reports whether l's answer says it serves datagrams.
func (l *Listener) Datagram() bool { return hasHint(l.hints, HintDatagram) }

// TakesDirect reports whether l's answer says it takes direct paths.
func (l *Listener) TakesDirect() bool { return TakesDirect(l.hints) }

// Anonymous reports whether l's answer says it is served with no account.
func (l *Listener) Anonymous() bool { return Anonymous(l.hints) }

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

// Admit runs steps 2-4 at the server on conn, its answer written, for a
// plain session: the TLS stream of an admitted client, or an error (conn
// is the caller's to close; a framed session is ErrKindRefused, no
// verdict). It sets no deadline (Accept bounds it).
func (l *Listener) Admit(ctx context.Context, conn net.Conn) (*tls.Conn, error) {
	tc, _, err := l.admit(ctx, conn, false)
	return tc, err
}

// AdmitKind is Admit that also takes a framed session: the admitted TLS
// stream and the session's kind (KindPlain or KindFramed; another is
// ErrKindRefused, and a plain one to a listener served with no account
// ErrDirectRequired, no verdict either way).
func (l *Listener) AdmitKind(ctx context.Context, conn net.Conn) (*tls.Conn, byte, error) {
	return l.admit(ctx, conn, true)
}

func (l *Listener) admit(ctx context.Context, conn net.Conn, framed bool) (*tls.Conn, byte, error) {
	cfg := l.cfg
	if framed {
		cfg = l.framed
	}
	tc := tls.Server(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, 0, err
	}
	kind := byte(KindPlain)
	if tc.ConnectionState().NegotiatedProtocol == ALPNFramed {
		kind = KindFramed
	}
	exp, err := capaddr.Exporter(tc.ConnectionState())
	if err != nil {
		return nil, 0, err
	}
	var proof [capaddr.ProofSize]byte
	if _, err := io.ReadFull(tc, proof[:]); err != nil {
		return nil, 0, err
	}
	if err := capaddr.Admit(l.addr.Secret, exp, proof[:]); err != nil {
		return nil, 0, err
	}
	if framed && kind == KindPlain && l.Anonymous() { // AdmitKind's: a session (Admit's are a control exchange's too)
		return nil, 0, ErrDirectRequired // a session that could never leave the relay: no verdict
	}
	if _, err := tc.Write([]byte{Admitted}); err != nil {
		return nil, 0, err
	}
	return tc, kind, nil
}

// Handshake runs the client's side of steps 1-4 on conn, a session the
// relay opened toward addr: the TLS stream to the admitted service, or
// capaddr.ErrPin, ErrRendezvous or ErrTLS (the server is not the address's:
// exit 7), ErrKind (the address serves datagrams), capaddr.ErrProof (the stream ended with no verdict: the secret refused, exit 10),
// ErrAnswer or a connection error. conn is closed on an error.
func Handshake(ctx context.Context, conn net.Conn, addr capaddr.Address) (net.Conn, error) {
	defer bound(ctx, conn)()
	tc, err := handshake(ctx, conn, addr, false)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

// HandshakeDatagram is Handshake for a datagram dial: the answer must say
// the address serves datagrams (ErrKind otherwise).
func HandshakeDatagram(ctx context.Context, conn net.Conn, addr capaddr.Address) (net.Conn, error) {
	defer bound(ctx, conn)()
	tc, err := handshake(ctx, conn, addr, true)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

func handshake(ctx context.Context, conn net.Conn, addr capaddr.Address, datagram bool) (net.Conn, error) {
	hints, err := ReadAnswer(conn, addr)
	if err != nil {
		return nil, err
	}
	if err := CheckKind(hints, datagram); err != nil {
		return nil, err
	}
	if Anonymous(hints) { // no framing here: the session could never leave the relay
		return nil, ErrDirectRequired
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

// ClientTLS runs steps 2-4 at the client on conn, the answer read, for a
// plain session: the TLS stream to the admitted service, or
// capaddr.ErrPin, ErrTLS, ErrProof or a connection error (conn is the
// caller's to close). It sets no deadline.
func ClientTLS(ctx context.Context, conn net.Conn, addr capaddr.Address) (*tls.Conn, error) {
	return clientTLS(ctx, conn, addr, KindPlain)
}

// ClientTLSFramed is ClientTLS for a session framed for direct paths
// (KindFramed): link pathswitch runs inside the returned TLS.
func ClientTLSFramed(ctx context.Context, conn net.Conn, addr capaddr.Address) (*tls.Conn, error) {
	return clientTLS(ctx, conn, addr, KindFramed)
}

func clientTLS(ctx context.Context, conn net.Conn, addr capaddr.Address, kind byte) (*tls.Conn, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, // #nosec G402 -- the pin replaces the CA: VerifyConnection
		VerifyConnection:   addr.VerifyConnection,
		ServerName:         "nf1",
	}
	if kind == KindFramed {
		cfg.NextProtos = []string{ALPNFramed}
	}
	tc := tls.Client(conn, cfg)
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
	if kind == KindFramed && tc.ConnectionState().NegotiatedProtocol != ALPNFramed {
		return nil, ErrKindRefused // the listener takes no framed session (no direct paths)
	}
	if _, err := tc.Write(proof[:]); err != nil {
		return nil, err
	}
	// The listener refuses by ending the stream with no verdict; a reset
	// or a failed connection is no verdict on the secret (a listener that
	// admits a session and resets it at once: nfltr-pipe's second dial).
	var v [1]byte
	if _, err := io.ReadFull(tc, v[:]); err != nil && err != io.EOF {
		return nil, err
	} else if err != nil || v[0] != Admitted {
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
