// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package capaddr is the capability address nf1...: its codec and the
// checks its clients and servers make, as spec/proverif/cap_address.pv
// fixes them (README "cap_address.pv"). Pure functions: no network; the
// rendezvous and the transport use them.
//
// An address A = (R, rid, pin, sec) names one service of one server:
//
//	R    the relay host the server registered at
//	rid  the rendezvous id: RIDOf(Nonce(sec), pk), bound to the server's key
//	pin  Pin(sec, pk): the server's TLS key keyed by the secret
//	sec  the secret, 32 random bytes, never all zeros
//
// Text form: "nf1" + base32 (lowercase, no padding) of
// version | len(R) | R | rid | pin | sec | CRC-32C of the bytes before it.
//
// The flow (the model's numbering): the server registers rid with
// SignRecord; the client opens only at R, takes the relay's answer (key,
// record, hints) only if CheckAnswer accepts it (BIND:cap.pin,
// BIND:cap.rendezvous), runs TLS 1.3 whose certificate key VerifyConnection
// pins (BIND:cap.pin), and sends Proof over this session's Exporter as its
// first record (BIND:cap.secret); the server runs Admit with the secret of
// the address the session was routed to before any service byte
// (BIND:cap.service). The server declares rid at R with RegistrationProof,
// which R checks with CheckRegistration (BIND:cap.register), so only the
// holder of the server key makes R serve rid.
package capaddr

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net/url"
	"strings"
)

// Prefix starts every address's text form.
const Prefix = "nf1"

// Version is the only payload version this package reads and writes.
const Version = 1

// Field sizes.
const (
	RIDSize    = 16
	PinSize    = 32
	SecretSize = 32
	ProofSize  = 32
	maxRelay   = 255
)

// The model's domain-separation tags (labPin, labProof, labRdv) and the
// TLS exporter label (RFC 8446 7.5) of the proof.
const (
	tagPin        = "nf1-pin"
	tagProof      = "nf1-proof"
	tagRendezvous = "nf1-rdv"
	tagNonce      = "nf1-n"
	tagRID        = "nf1-rid"
	tagRegister   = "nf1-reg"
	ExporterLabel = "EXPORTER-nf1-proof"
)

// Parse errors (errors.Is): every bad address is one of these.
var (
	ErrNotAddress = errors.New("nf1: not a capability address (want nf1... with no / or @)")
	ErrEncoding   = errors.New("nf1: bad encoding")
	ErrChecksum   = errors.New("nf1: checksum mismatch (a typo?)")
	ErrVersion    = errors.New("nf1: unknown version")
	ErrLength     = errors.New("nf1: missing or extra field bytes")
	ErrSecret     = errors.New("nf1: all-zero secret")
	ErrRelay      = errors.New("nf1: bad relay host")
)

// Check errors: a refusal of the rendezvous answer, the TLS session or a
// proof.
var (
	ErrPin        = errors.New("nf1: server key does not match the address's pin")
	ErrRendezvous = errors.New("nf1: rendezvous record not signed by the pinned key over this relay, rid and hints")
	ErrTLS        = errors.New("nf1: TLS session refused")
	ErrProof      = errors.New("nf1: proof refused")
	ErrRegister   = errors.New("nf1: registration proof refused (rid not bound to this key, or not signed by it over this relay and rid)")
)

var (
	b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	crc = crc32.MakeTable(crc32.Castagnoli)
)

// Address is A = (R, rid, pin, sec).
type Address struct {
	Relay  string
	RID    [RIDSize]byte
	Pin    [PinSize]byte
	Secret [SecretSize]byte
}

// New draws sec from crypto/rand for a server at relay whose TLS public
// key is spki (DER SubjectPublicKeyInfo) and computes rid (RIDOf) and the
// pin.
func New(relay string, spki []byte) (Address, error) {
	if err := checkRelay(relay); err != nil {
		return Address{}, err
	}
	a := Address{Relay: relay}
	for a.Secret == ([SecretSize]byte{}) {
		_, _ = rand.Read(a.Secret[:]) // crypto/rand.Read never fails (Go 1.24+)
	}
	a.RID = RIDOf(Nonce(a.Secret), spki)
	a.Pin = Pin(a.Secret, spki)
	return a, nil
}

// String is Format's text, or "" for an address Format refuses.
func (a Address) String() string {
	s, _ := Format(a)
	return s
}

// Format is the address's text form. It refuses what Parse refuses: a
// relay that is not a host[:port] of at most 255 bytes, an all-zero
// secret.
func Format(a Address) (string, error) {
	if err := checkRelay(a.Relay); err != nil {
		return "", err
	}
	if a.Secret == ([SecretSize]byte{}) {
		return "", ErrSecret
	}
	return format(a), nil
}

func format(a Address) string {
	b := make([]byte, 0, 2+len(a.Relay)+RIDSize+PinSize+SecretSize+4)
	b = append(b, Version, byte(len(a.Relay))) // #nosec G115 -- checkRelay bounds len(R) to 255
	b = append(b, a.Relay...)
	b = append(b, a.RID[:]...)
	b = append(b, a.Pin[:]...)
	b = append(b, a.Secret[:]...)
	b = binary.BigEndian.AppendUint32(b, crc32.Checksum(b, crc))
	return Prefix + b32.EncodeToString(b)
}

// Parse reads an address offline. It refuses a text that does not start
// with nf1 or holds / or @ (the target grammar's other forms), a bad
// encoding or checksum, an unknown version, a missing or extra byte, an
// all-zero secret and a relay that is not a host[:port]; and it accepts
// only the canonical text (Format of the result).
func Parse(s string) (Address, error) {
	if !strings.HasPrefix(s, Prefix) || strings.ContainsAny(s, "/@") {
		return Address{}, ErrNotAddress
	}
	b, err := b32.DecodeString(s[len(Prefix):])
	if err != nil {
		return Address{}, ErrEncoding
	}
	if len(b) < 1+4 {
		return Address{}, ErrLength
	}
	body, sum := b[:len(b)-4], binary.BigEndian.Uint32(b[len(b)-4:])
	if crc32.Checksum(body, crc) != sum {
		return Address{}, ErrChecksum
	}
	if body[0] != Version {
		return Address{}, fmt.Errorf("%w %d", ErrVersion, body[0])
	}
	if len(body) < 2 || len(body) != 2+int(body[1])+RIDSize+PinSize+SecretSize {
		return Address{}, ErrLength
	}
	n := int(body[1])
	a := Address{Relay: string(body[2 : 2+n])}
	rest := body[2+n:]
	copy(a.RID[:], rest)
	copy(a.Pin[:], rest[RIDSize:])
	copy(a.Secret[:], rest[RIDSize+PinSize:])
	if a.Secret == ([SecretSize]byte{}) {
		return Address{}, ErrSecret
	}
	if err := checkRelay(a.Relay); err != nil {
		return Address{}, err
	}
	if format(a) != s { // non-zero trailing bits of the last base32 character
		return Address{}, ErrEncoding
	}
	return a, nil
}

// checkRelay: a non-empty host or host:port of at most 255 bytes, nothing
// else (no user, path, query or fragment).
func checkRelay(r string) error {
	if r == "" || len(r) > maxRelay {
		return ErrRelay
	}
	u, err := url.Parse("//" + r)
	if err != nil || u.Host != r || u.Hostname() == "" {
		return ErrRelay
	}
	return nil
}

// Pin is pinOf(sec, pk) = HMAC-SHA256(sec, "nf1-pin" || spki): the
// server's key keyed by the secret, so whoever sees the key without the
// secret cannot compute it. spki is the key's DER SubjectPublicKeyInfo (a
// certificate's RawSubjectPublicKeyInfo).
func Pin(sec [SecretSize]byte, spki []byte) [PinSize]byte {
	return mac(sec, tagPin, spki)
}

// CheckKey requires a server key to match the pin (BIND:cap.pin): the
// rendezvous answer's key and the TLS certificate's key both.
func (a Address) CheckKey(spki []byte) error {
	p := Pin(a.Secret, spki)
	if subtle.ConstantTimeCompare(p[:], a.Pin[:]) != 1 {
		return ErrPin
	}
	return nil
}

// rendezvousMessage is what a record signs: "nf1-rdv" | len(R) | R | rid |
// hints (hints last, so the encoding is injective).
func rendezvousMessage(relay string, rid [RIDSize]byte, hints []byte) []byte {
	b := make([]byte, 0, len(tagRendezvous)+2+len(relay)+RIDSize+len(hints))
	b = append(b, tagRendezvous...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(relay))) // #nosec G115 -- callers checkRelay: at most 255
	b = append(b, relay...)
	b = append(b, rid[:]...)
	return append(b, hints...)
}

// SignRecord is the server's registration record Sign_sk("nf1-rdv", R,
// rid, hints); hints is whatever a client acts on before TLS (direct
// candidates), opaque here.
//
// ponytail: Ed25519 keys only; add ECDSA when a server needs another key.
func SignRecord(sk ed25519.PrivateKey, relay string, rid [RIDSize]byte, hints []byte) ([]byte, error) {
	if err := checkRelay(relay); err != nil {
		return nil, err
	}
	return ed25519.Sign(sk, rendezvousMessage(relay, rid, hints)), nil
}

// VerifyRecord checks rec under the key spki over the tag, relay, rid and
// hints.
func VerifyRecord(spki, rec []byte, relay string, rid [RIDSize]byte, hints []byte) error {
	if checkRelay(relay) != nil {
		return ErrRendezvous
	}
	k, err := x509.ParsePKIXPublicKey(spki)
	pub, ok := k.(ed25519.PublicKey)
	if err != nil || !ok || !ed25519.Verify(pub, rendezvousMessage(relay, rid, hints), rec) {
		return ErrRendezvous
	}
	return nil
}

// CheckAnswer is the client's check of the rendezvous answer (key, record,
// hints) from the relay it opened at, which is always a.Relay: the key
// matches the pin (BIND:cap.pin) and the record is signed under that key
// over a.Relay, a.RID and hints (BIND:cap.rendezvous). Only then may the
// client use hints or open TLS. A "plain" answer has no key and fails.
func (a Address) CheckAnswer(spki, rec, hints []byte) error {
	if err := a.CheckKey(spki); err != nil {
		return err
	}
	return VerifyRecord(spki, rec, a.Relay, a.RID, hints)
}

// VerifyConnection is the client's check of its TLS session (a
// tls.Config.VerifyConnection, with InsecureSkipVerify: the pin replaces
// the CA): TLS 1.3 and a server certificate whose key matches the pin
// (BIND:cap.pin).
func (a Address) VerifyConnection(cs tls.ConnectionState) error {
	if cs.Version != tls.VersionTLS13 || len(cs.PeerCertificates) == 0 {
		return ErrTLS
	}
	return a.CheckKey(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
}

// Exporter is the session's exporter the proof binds (RFC 8446 7.5: it
// covers the whole handshake transcript, the server's certificate
// included).
func Exporter(cs tls.ConnectionState) ([]byte, error) {
	if cs.Version != tls.VersionTLS13 {
		return nil, ErrTLS
	}
	return cs.ExportKeyingMaterial(ExporterLabel, nil, 32)
}

// Proof is H("nf1-proof", sec, exporter) = HMAC-SHA256(sec, "nf1-proof" ||
// exporter): the client's first record inside TLS (BIND:cap.secret).
func Proof(sec [SecretSize]byte, exporter []byte) [ProofSize]byte {
	return mac(sec, tagProof, exporter)
}

// Admit is the server's check of a session's first record: sec is the
// secret of the address the session was routed to, never another address's
// of the same key (BIND:cap.service). Constant time. On an error the
// server closes the session; no service code runs before Admit returns nil.
func Admit(sec [SecretSize]byte, exporter, proof []byte) error {
	want := Proof(sec, exporter)
	if len(exporter) == 0 || !hmac.Equal(want[:], proof) {
		return ErrProof
	}
	return nil
}

func mac(sec [SecretSize]byte, tag string, data []byte) [32]byte {
	m := hmac.New(sha256.New, sec[:])
	m.Write([]byte(tag))
	m.Write(data)
	var out [32]byte
	m.Sum(out[:0])
	return out
}

// Nonce is the rid's nonce n = HMAC-SHA256(sec, "nf1-n")[:16]: fresh per
// address, public (the relay learns it from the registration proof), and
// it reveals nothing of sec.
func Nonce(sec [SecretSize]byte) [RIDSize]byte {
	m := mac(sec, tagNonce, nil)
	return [RIDSize]byte(m[:RIDSize])
}

// RIDOf is ridOf(n, pk) = SHA-256("nf1-rid" || n || spki)[:16]: the rid
// bound to the server's key, so another key cannot claim it without a
// second preimage.
func RIDOf(n [RIDSize]byte, spki []byte) [RIDSize]byte {
	h := sha256.New()
	h.Write([]byte(tagRID))
	h.Write(n[:])
	h.Write(spki)
	return [RIDSize]byte(h.Sum(nil)[:RIDSize])
}

// registerMessage is what a registration proof signs: "nf1-reg" | len(R) |
// R | rid.
func registerMessage(relay string, rid [RIDSize]byte) []byte {
	b := make([]byte, 0, len(tagRegister)+2+len(relay)+RIDSize)
	b = append(b, tagRegister...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(relay))) // #nosec G115 -- callers checkRelay: at most 255
	b = append(b, relay...)
	return append(b, rid[:]...)
}

// RegistrationProof is what the server sends R, and only R, with its
// declaration of a.RID: n | len(spki) (2 bytes) | spki | Ed25519_sk("nf1-reg",
// R, rid). It refuses (ErrRegister) an address whose rid is not RIDOf(n,
// sk's key): one minted before rids were bound to keys, or another key's.
func RegistrationProof(sk ed25519.PrivateKey, a Address) ([]byte, error) {
	if err := checkRelay(a.Relay); err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(sk.Public())
	if err != nil {
		return nil, err
	}
	n := Nonce(a.Secret)
	if RIDOf(n, spki) != a.RID {
		return nil, ErrRegister
	}
	b := make([]byte, 0, RIDSize+2+len(spki)+ed25519.SignatureSize)
	b = append(b, n[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(spki))) // #nosec G115 -- an Ed25519 SPKI is 44 bytes
	b = append(b, spki...)
	return append(b, ed25519.Sign(sk, registerMessage(a.Relay, a.RID))...), nil
}

// CheckRegistration is R's check of a declaration of rid at relay (R's own
// host, the one its addresses name) (BIND:cap.register): rid = RIDOf(n,
// spki) and the signature under spki over the tag, relay and rid. The
// rendezvous record, which every opener gets, is under another tag and
// never passes.
func CheckRegistration(relay string, rid [RIDSize]byte, proof []byte) error {
	if checkRelay(relay) != nil || len(proof) < RIDSize+2 {
		return ErrRegister
	}
	n := [RIDSize]byte(proof[:RIDSize])
	l := int(binary.BigEndian.Uint16(proof[RIDSize:]))
	rest := proof[RIDSize+2:]
	if len(rest) != l+ed25519.SignatureSize {
		return ErrRegister
	}
	spki, sig := rest[:l], rest[l:]
	k, err := x509.ParsePKIXPublicKey(spki)
	pub, ok := k.(ed25519.PublicKey)
	if err != nil || !ok || RIDOf(n, spki) != rid || !ed25519.Verify(pub, registerMessage(relay, rid), sig) {
		return ErrRegister
	}
	return nil
}
