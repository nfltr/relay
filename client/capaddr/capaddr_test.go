// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package capaddr

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// seq is n bytes from start, start+1, ...
func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// fixedKey is the vectors' server key.
func fixedKey(t testing.TB) (ed25519.PrivateKey, []byte) {
	sk := ed25519.NewKeyFromSeed(seq(0x40, ed25519.SeedSize))
	spki, err := x509.MarshalPKIXPublicKey(sk.Public())
	if err != nil {
		t.Fatal(err)
	}
	return sk, spki
}

func newKey(t testing.TB) (ed25519.PrivateKey, []byte) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(sk.Public())
	if err != nil {
		t.Fatal(err)
	}
	return sk, spki
}

// fixedAddress is the vectors' address.
func fixedAddress(t testing.TB) Address {
	_, spki := fixedKey(t)
	a := Address{Relay: "relay.example.com"}
	copy(a.RID[:], seq(0x00, RIDSize))
	copy(a.Secret[:], seq(0x20, SecretSize))
	a.Pin = Pin(a.Secret, spki)
	return a
}

// encode is Format's framing over any body: a test writes payloads Format
// would not.
func encode(body []byte) string {
	b := binary.BigEndian.AppendUint32(append([]byte(nil), body...), crc32.Checksum(body, crc))
	return Prefix + b32.EncodeToString(b)
}

// payload is the fixed address's body (no checksum).
func payload(t testing.TB) []byte {
	s := Format(fixedAddress(t))
	b, err := b32.DecodeString(s[len(Prefix):])
	if err != nil {
		t.Fatal(err)
	}
	return b[:len(b)-4]
}

func TestRoundTrip(t *testing.T) {
	_, spki := newKey(t)
	for _, relay := range []string{"relay.example.com", "r.example:8443", "[2001:db8::1]:443", "localhost"} {
		a, err := New(relay, spki)
		if err != nil {
			t.Fatalf("New(%q): %v", relay, err)
		}
		if err := a.CheckKey(spki); err != nil {
			t.Fatalf("New's pin: %v", err)
		}
		s := a.String()
		if !strings.HasPrefix(s, Prefix) || strings.ContainsAny(s, "/@") {
			t.Fatalf("%q: not an nf1 target", s)
		}
		got, err := Parse(s)
		if err != nil || got != a {
			t.Fatalf("Parse(Format(a)) = %+v, %v; want %+v", got, err, a)
		}
	}
	b, _ := New("relay.example.com", spki)
	c, _ := New("relay.example.com", spki)
	if b.RID == c.RID || b.Secret == c.Secret || b.Pin == c.Pin {
		t.Fatal("two New addresses share a field")
	}
}

func TestNewRefusesBadRelay(t *testing.T) {
	_, spki := newKey(t)
	for _, r := range []string{"", "a/b", "u@host", "host?q", "host#f", ":443", strings.Repeat("a", 256)} {
		if _, err := New(r, spki); !errors.Is(err, ErrRelay) {
			t.Errorf("New(%q) = %v, want ErrRelay", r, err)
		}
	}
}

// Every single-character substitution and every adjacent transposition of
// an address fails (CRC-32C detects every burst of up to 32 bits; one
// base32 character is 5, two adjacent 10).
func TestTypoFailsChecksum(t *testing.T) {
	s := Format(fixedAddress(t))
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	for i := len(Prefix); i < len(s); i++ {
		for _, c := range alphabet {
			if byte(c) == s[i] {
				continue
			}
			typo := s[:i] + string(c) + s[i+1:]
			if _, err := Parse(typo); err == nil {
				t.Fatalf("substitution at %d (%c) parsed", i, c)
			}
		}
		if i+1 < len(s) && s[i] != s[i+1] {
			swap := s[:i] + string(s[i+1]) + string(s[i]) + s[i+2:]
			if _, err := Parse(swap); err == nil {
				t.Fatalf("transposition at %d parsed", i)
			}
		}
	}
	if _, err := Parse(s[:len(s)-1]); err == nil {
		t.Fatal("a truncated address parsed")
	}
}

func TestParseRefusals(t *testing.T) {
	body := payload(t)
	with := func(f func(b []byte) []byte) string { return encode(f(append([]byte(nil), body...))) }
	shortSecret := with(func(b []byte) []byte { return b[:len(b)-1] })
	longSecret := with(func(b []byte) []byte { return append(b, 1) })
	zeroSecret := with(func(b []byte) []byte {
		clear(b[len(b)-SecretSize:])
		return b
	})
	version2 := with(func(b []byte) []byte { b[0] = 2; return b })
	version0 := with(func(b []byte) []byte { b[0] = 0; return b })
	badRelay := encode(append([]byte{Version, 3, 'a', '/', 'b'}, body[2+len("relay.example.com"):]...))
	noRelay := encode(append([]byte{Version, 0}, body[2+len("relay.example.com"):]...))
	good := Format(fixedAddress(t))
	for _, c := range []struct {
		s    string
		want error
	}{
		{"", ErrNotAddress},
		{"home/db", ErrNotAddress},
		{"pg@db", ErrNotAddress},
		{"nf1abc/db", ErrNotAddress},
		{"nf1abc@x", ErrNotAddress},
		{strings.ToUpper(good), ErrNotAddress},
		{Prefix + strings.ToUpper(good[len(Prefix):]), ErrEncoding},
		{good + "=", ErrEncoding},
		{Prefix, ErrLength},
		{shortSecret, ErrLength},
		{longSecret, ErrLength},
		{zeroSecret, ErrSecret},
		{version2, ErrVersion},
		{version0, ErrVersion},
		{badRelay, ErrRelay},
		{noRelay, ErrRelay},
	} {
		if _, err := Parse(c.s); !errors.Is(err, c.want) {
			t.Errorf("Parse(%.40q) = %v, want %v", c.s, err, c.want)
		}
	}
}

// A last character whose unused low bits are set decodes to the same
// bytes; only the canonical text parses.
func TestParseRefusesNonCanonical(t *testing.T) {
	s := Format(fixedAddress(t))
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	i := strings.IndexByte(alphabet, s[len(s)-1])
	n := 0
	for j := range alphabet {
		if j == i {
			continue
		}
		alt := s[:len(s)-1] + string(alphabet[j])
		b, err := b32.DecodeString(alt[len(Prefix):])
		if err != nil {
			continue
		}
		if want, _ := b32.DecodeString(s[len(Prefix):]); bytes.Equal(b, want) {
			n++
			if _, err := Parse(alt); !errors.Is(err, ErrEncoding) {
				t.Errorf("non-canonical %q: %v", alt, err)
			}
		}
	}
	if n == 0 {
		t.Fatal("no non-canonical spelling tried: the fixed address's last character carries an unused bit")
	}
}

func TestAdmitAndProof(t *testing.T) {
	a := fixedAddress(t)
	exp := seq(0x60, 32)
	p := Proof(a.Secret, exp)
	if err := Admit(a.Secret, exp, p[:]); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, p[:31], append(p[:], 0)} {
		if err := Admit(a.Secret, exp, bad); !errors.Is(err, ErrProof) {
			t.Errorf("Admit(%x) = %v", bad, err)
		}
	}
	if err := Admit(a.Secret, nil, func() []byte { q := Proof(a.Secret, nil); return q[:] }()); !errors.Is(err, ErrProof) {
		t.Error("Admit took a proof over no exporter")
	}
	// The tags separate the pin and the proof under one secret.
	if Pin(a.Secret, exp) == Proof(a.Secret, exp) {
		t.Fatal("pin and proof collide")
	}
}

// vectors is testdata/vectors.json: the fixed inputs, the outputs every
// implementation of the format must produce, and refused texts.
type vectors struct {
	Relay    string `json:"relay"`
	RID      string `json:"rid"`
	Secret   string `json:"secret"`
	KeySeed  string `json:"ed25519_seed"`
	SPKI     string `json:"spki"`
	Pin      string `json:"pin"`
	Address  string `json:"address"`
	Hints    string `json:"hints"`
	Record   string `json:"record"`
	Exporter string `json:"exporter"`
	Proof    string `json:"proof"`
	Refused  []struct {
		Text  string `json:"text"`
		Error string `json:"error"`
	} `json:"refused"`
}

func computeVectors(t *testing.T) vectors {
	sk, spki := fixedKey(t)
	a := fixedAddress(t)
	hints := []byte("hints")
	exp := seq(0x60, 32)
	p := Proof(a.Secret, exp)
	v := vectors{
		Relay: a.Relay, RID: hex.EncodeToString(a.RID[:]), Secret: hex.EncodeToString(a.Secret[:]),
		KeySeed: hex.EncodeToString(sk.Seed()), SPKI: hex.EncodeToString(spki), Pin: hex.EncodeToString(a.Pin[:]),
		Address: Format(a), Hints: hex.EncodeToString(hints),
		Record:   hex.EncodeToString(SignRecord(sk, a.Relay, a.RID, hints)),
		Exporter: hex.EncodeToString(exp), Proof: hex.EncodeToString(p[:]),
	}
	body := payload(t)
	s := v.Address
	sub := byte('a')
	if s[10] == 'a' {
		sub = 'b'
	}
	typo := s[:10] + string(sub) + s[11:]
	zero := append([]byte(nil), body...)
	clear(zero[len(zero)-SecretSize:])
	v2 := append([]byte(nil), body...)
	v2[0] = 2
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	for _, r := range []struct{ text, err string }{
		{typo, "checksum"},
		{encode(v2), "version"},
		{encode(zero), "secret"},
		{encode(body[:len(body)-1]), "length"},
		{s[:len(s)-1] + string(alphabet[strings.IndexByte(alphabet, s[len(s)-1])^1]), "encoding"}, // the unused low bit set
	} {
		v.Refused = append(v.Refused, struct {
			Text  string `json:"text"`
			Error string `json:"error"`
		}{r.text, r.err})
	}
	return v
}

var errNames = map[string]error{"checksum": ErrChecksum, "version": ErrVersion, "secret": ErrSecret, "length": ErrLength, "encoding": ErrEncoding}

// TestVectors: NF1_WRITE_VECTORS=1 rewrites testdata/vectors.json.
func TestVectors(t *testing.T) {
	got := computeVectors(t)
	path := "testdata/vectors.json"
	if os.Getenv("NF1_WRITE_VECTORS") == "1" {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want vectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if !bytes.Equal(gb, wb) {
		t.Fatalf("vectors differ from %s:\n got %s\nwant %s", path, gb, wb)
	}
	a, err := Parse(want.Address)
	if err != nil || a != fixedAddress(t) {
		t.Fatalf("Parse(vector) = %+v, %v", a, err)
	}
	for _, r := range want.Refused {
		if _, err := Parse(r.Text); !errors.Is(err, errNames[r.Error]) {
			t.Errorf("Parse(%q) = %v, want %s", r.Text, err, r.Error)
		}
	}
}

// selfSigned is a TLS certificate for sk.
func selfSigned(t testing.TB, sk ed25519.PrivateKey) tls.Certificate {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, sk.Public(), sk)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: sk}
}

// session runs TLS 1.3 over a pipe: a server with sk's certificate, a
// client of a (VerifyConnection, no certificate of its own). It returns the
// client's error and both ends' exporters.
func session(t testing.TB, a Address, sk ed25519.PrivateKey) (clientExp, serverExp []byte, err error) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	srv := tls.Server(s, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, sk)}, MinVersion: tls.VersionTLS13})
	cli := tls.Client(c, &tls.Config{InsecureSkipVerify: true, VerifyConnection: a.VerifyConnection, MinVersion: tls.VersionTLS13}) // #nosec G402 -- the pin replaces the CA
	done := make(chan error, 1)
	go func() { done <- srv.Handshake() }()
	err = cli.Handshake()
	if err != nil {
		c.Close()
		<-done
		return nil, nil, err
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if clientExp, err = Exporter(cli.ConnectionState()); err != nil {
		t.Fatal(err)
	}
	if serverExp, err = Exporter(srv.ConnectionState()); err != nil {
		t.Fatal(err)
	}
	if len(srv.ConnectionState().PeerCertificates) != 0 {
		t.Fatal("the client presented a certificate")
	}
	return clientExp, serverExp, nil
}
