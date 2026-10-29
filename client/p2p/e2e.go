// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/nfltr/relay/client/rpcclient"
)

// End-to-end encryption of every p2p session (signaling protocol 3). The
// offer and the
// answer carry each side's ephemeral X25519 public key; the relay sees only
// those. Both sides derive, with HKDF-SHA256 over the shared secret (salted
// with the pairing key when there is one) and the transcript (session ID and
// both public keys), the keys for:
//
//   - the data stream on every path (Secure: AES-256-GCM records),
//   - the signaling frames on every path (E2E.SignalConn: sealed frames),
//   - the direct TCP channel's handshake (DirectToken),
//   - the key confirmation exchanged right after the answer, and
//   - the session fingerprint both CLIs print.
//
// Without a pairing key a relay that replaces both public keys sits in the
// middle unnoticed except by the fingerprint (different on the two
// machines); with the same pairing key on both machines it cannot: the key
// confirmation fails.

// ErrE2EMismatch is a failed key confirmation: the two sides derived
// different keys.
var ErrE2EMismatch = errors.New("p2p: end-to-end key check failed: the two machines use different " +
	"pairing keys (--e2ee-key-file / NFLTR_A2A_E2EE_KEY_FILE; set the same file on both, or none), " +
	"or something between them (the relay) replaced the keys")

// errE2ETampered is a record or sealed frame that does not authenticate.
var errE2ETampered = errors.New("p2p: end-to-end check failed: data was altered in transit")

// E2E is one side's end-to-end key exchange for one session.
type E2E struct {
	sessionID string
	initiator bool
	pairing   []byte
	priv      *ecdh.PrivateKey
	prk, th   []byte // set by Complete
}

// NewE2E starts this side's key exchange with a fresh ephemeral key.
// pairing is the 32-byte pairing key (rpcclient.LoadA2AE2EEPairingKey), or
// nil.
func NewE2E(sessionID string, initiator bool, pairing []byte) (*E2E, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("p2p: end-to-end key: %w", err)
	}
	return &E2E{sessionID: sessionID, initiator: initiator, pairing: pairing, priv: priv}, nil
}

// PublicKey is this side's public key for the offer or answer (hex).
// allow:wrapper
func (e *E2E) PublicKey() string { return hex.EncodeToString(e.priv.PublicKey().Bytes()) }

// Paired reports whether a pairing key authenticates the exchange.
func (e *E2E) Paired() bool { return e.pairing != nil }

// Complete derives the session keys from the peer's public key.
func (e *E2E) Complete(peerKey string) error {
	raw, err := hex.DecodeString(peerKey)
	if err != nil || len(raw) != 32 {
		return errors.New("p2p: the peer sent no valid end-to-end key")
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return fmt.Errorf("p2p: peer end-to-end key: %w", err)
	}
	shared, err := e.priv.ECDH(pub) // fails on a low-order point
	if err != nil {
		return fmt.Errorf("p2p: peer end-to-end key: %w", err)
	}
	own := e.priv.PublicKey().Bytes()
	ip, rp := own, raw
	if !e.initiator {
		ip, rp = raw, own
	}
	h := sha256.New()
	h.Write([]byte("nfltr-p2p-e2e-v1\x00" + e.sessionID + "\x00"))
	h.Write(ip)
	h.Write(rp)
	th := h.Sum(nil)
	prk, err := hkdf.Extract(sha256.New, shared, e.pairing)
	if err != nil {
		return err
	}
	e.prk, e.th = prk, th
	return nil
}

func (e *E2E) key(label string, n int) []byte {
	if e.prk == nil {
		panic("p2p: E2E used before Complete")
	}
	k, err := hkdf.Expand(sha256.New, e.prk, label+"\x00"+string(e.th), n)
	if err != nil {
		panic(err) // only for n > 255*32
	}
	return k
}

func role(initiator bool) string {
	if initiator {
		return "initiator"
	}
	return "responder"
}

// confirmTag is the key confirmation the initiator (true) or responder sends.
func (e *E2E) confirmTag(initiator bool) string {
	m := hmac.New(sha256.New, e.key("confirm", 32))
	m.Write([]byte(role(initiator)))
	return hex.EncodeToString(m.Sum(nil))
}

// Confirm is this side's key confirmation. allow:wrapper
func (e *E2E) Confirm() string { return e.confirmTag(e.initiator) }

// checkConfirm verifies the peer's key confirmation.
func (e *E2E) checkConfirm(tag string) error {
	if !hmac.Equal([]byte(tag), []byte(e.confirmTag(!e.initiator))) {
		return ErrE2EMismatch
	}
	return nil
}

// Fingerprint is the session fingerprint (80 bits) both CLIs print: the same
// on both machines unless something in the middle replaced the keys.
func (e *E2E) Fingerprint() string {
	s := strings.ToUpper(hex.EncodeToString(e.key("fingerprint", 10)))
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20]
}

// DirectToken is the direct TCP channel's handshake secret (Connect,
// TCPDirect): known only to the two ends, never sent. allow:wrapper
func (e *E2E) DirectToken() []byte { return e.key("direct-tcp", 32) }

// Answer (responder) completes the exchange with the offer's key and fills
// the answer's key and key confirmation.
func (e *E2E) Answer(offer, answer *SignalMsg) error {
	if err := e.Complete(offer.Key); err != nil {
		return err
	}
	answer.Key, answer.Confirm = e.PublicKey(), e.Confirm()
	return nil
}

// FinishOffer (initiator) completes the exchange with the answer and checks
// its key confirmation, then sends this side's confirmation on stream, or a
// hangup naming the failure (the responder prints it).
func (e *E2E) FinishOffer(stream rpcclient.ClientStream, answer *SignalMsg) error {
	err := e.Complete(answer.Key)
	if err == nil {
		err = e.checkConfirm(answer.Confirm)
	}
	msg := &SignalMsg{Type: SignalHangup, Session: e.sessionID}
	if err != nil {
		msg.Error = err.Error()
	} else {
		msg.Type, msg.Confirm = SignalConfirm, e.Confirm()
	}
	b, _ := json.Marshal(msg)
	if serr := stream.Send(b); err == nil {
		err = serr
	}
	return err
}

// AwaitConfirm (responder) reads the initiator's key confirmation, the
// message after the answer.
func (e *E2E) AwaitConfirm(stream rpcclient.ServerStream) error {
	m, err := RecvSignalServer(stream)
	if err != nil {
		return err
	}
	switch m.Type {
	case SignalConfirm:
		return e.checkConfirm(m.Confirm)
	case SignalHangup:
		return fmt.Errorf("p2p: the peer ended the session: %s", m.Error)
	}
	return fmt.Errorf("p2p: expected the peer's key confirmation, got %q", m.Type)
}

// direction keys: this side writes with out, reads with in.
func (e *E2E) aeads(label string) (out, in cipher.AEAD) {
	i2r, r2i := newGCM(e.key(label+" i2r", 32)), newGCM(e.key(label+" r2i", 32))
	if e.initiator {
		return i2r, r2i
	}
	return r2i, i2r
}

func newGCM(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // 32-byte key
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return g
}

// nonce is a record or frame's GCM nonce: its sequence number. Each key is
// used in one direction of one stream (or one SignalConn), so no nonce
// repeats under a key.
func nonce(seq uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// secureRecordMax is the largest plaintext in one record.
const secureRecordMax = 64 << 10

// Secure wraps a session's data conn (any path: direct TCP, WebRTC data
// channel, the relay) in AES-256-GCM records: 4-byte big-endian length, then
// the sealed bytes, nonce = the record's sequence number. A record that does
// not authenticate (altered, reordered, replayed, or from another key) fails
// every later Read. The relay can still cut the stream short; transfers
// check the size and SHA-256 inside it.
func (e *E2E) Secure(c net.Conn) net.Conn {
	out, in := e.aeads("data")
	return &secureConn{Conn: c, seal: out, open: in}
}

type secureConn struct {
	net.Conn
	seal, open cipher.AEAD

	wmu  sync.Mutex
	wseq uint64

	rmu  sync.Mutex
	rseq uint64
	raw  []byte
	rest []byte
	rerr error
}

func (c *secureConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n := 0
	for len(p) > 0 {
		k := min(len(p), secureRecordMax)
		rec := c.seal.Seal(make([]byte, 4, 4+k+c.seal.Overhead()), nonce(c.wseq), p[:k], nil)
		binary.BigEndian.PutUint32(rec, uint32(len(rec)-4))
		if _, err := c.Conn.Write(rec); err != nil {
			return n, err
		}
		c.wseq++
		n += k
		p = p[k:]
	}
	return n, nil
}

func (c *secureConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.rest) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		if err := c.readRecord(); err != nil {
			c.rerr = err
			return 0, err
		}
	}
	n := copy(p, c.rest)
	c.rest = c.rest[n:]
	return n, nil
}

func (c *secureConn) readRecord() error {
	var hdr [4]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return err // io.EOF between records: the peer closed
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < c.open.Overhead() || n > secureRecordMax+c.open.Overhead() {
		return errE2ETampered
	}
	if c.raw == nil {
		c.raw = make([]byte, secureRecordMax+c.open.Overhead())
	}
	if _, err := io.ReadFull(c.Conn, c.raw[:n]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	plain, err := c.open.Open(c.raw[:0], nonce(c.rseq), c.raw[:n], nil)
	if err != nil {
		return errE2ETampered
	}
	c.rseq++
	c.rest = plain
	return nil
}

// SignalConn starts a SignalConn whose paths (first, and every AddPath)
// carry sealed frames: the relay sees only their sequence numbers and sizes.
// OpenDataPath secures the data path with the same E2E.
func (e *E2E) SignalConn(first FramePath) *SignalConn {
	sc := NewSignalConn(e.sealPath(first))
	sc.e2e = e // before any AddPath: later paths are sealed too
	return sc
}

// frameSealed is the type of a sealed signaling frame (E2E.SignalConn).
const frameSealed FrameType = "sealed"

// sealedPath seals each frame with this direction's key; nonce = the frame's
// sequence number, which SignalConn assigns once and writes on every path
// (the same frame, the same ciphertext).
type sealedPath struct {
	p          FramePath
	seal, open cipher.AEAD
}

func (e *E2E) sealPath(p FramePath) FramePath {
	out, in := e.aeads("signal")
	return sealedPath{p: p, seal: out, open: in}
}

func (s sealedPath) WriteFrame(f *Frame) error {
	if f.Seq == 0 {
		return errors.New("p2p: a sealed frame needs a sequence number")
	}
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("p2p: marshal frame: %w", err)
	}
	ct := s.seal.Seal(nil, nonce(f.Seq), b, nil)
	return s.p.WriteFrame(&Frame{Type: frameSealed, Seq: f.Seq, Text: base64.StdEncoding.EncodeToString(ct)})
}

func (s sealedPath) ReadFrame() (*Frame, error) {
	f, err := s.p.ReadFrame()
	if err != nil {
		return nil, err
	}
	if f.Type != frameSealed || f.Seq == 0 {
		return nil, errE2ETampered
	}
	ct, err := base64.StdEncoding.DecodeString(f.Text)
	if err != nil {
		return nil, errE2ETampered
	}
	b, err := s.open.Open(nil, nonce(f.Seq), ct, nil)
	if err != nil {
		return nil, errE2ETampered
	}
	var g Frame
	if json.Unmarshal(b, &g) != nil || g.Seq != f.Seq {
		return nil, errE2ETampered
	}
	return &g, nil
}

// Close closes the underlying path (FramePath). allow:wrapper
func (s sealedPath) Close() error { return s.p.Close() }
