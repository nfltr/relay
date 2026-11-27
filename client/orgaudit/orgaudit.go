// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package orgaudit is the per-session audit record of an organisation's
// serving agent and the one check every reader runs (nfltr
// docs/decisions/service-access-2026-11-25.md "SA5: the record, its check,
// the names"; spec/proverif/svc_access.pv query 7, BIND:svc.auditsig).
//
// A record is metadata only: who (the client certificate's name, person,
// groups), which service, what admitted it, when it opened and closed, the
// bytes each way, why it ended. Never a byte of content. Each line of a
// machine's log is {"rec":{...},"sig":"..."}: the record, numbered (seq),
// chained to the line before (prev, its SHA-256) and signed by the
// machine's certified Ed25519 key over "nfltr-audit-v1\x00" and the exact
// bytes of rec (RFC 5848's signed syslog, Certificate Transparency's
// append-only log). A Checker finds a dropped, reordered, edited, forged
// or foreign record.
package orgaudit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The kinds of record: a session's admission and its end.
const (
	KindOpen  = "open"
	KindClose = "close"
)

// Why a session ended (Record.Reason).
const (
	ReasonClosed  = "closed"  // either side ended it
	ReasonExpiry  = "expiry"  // its admission's end (a grant's, a certificate's, the rules' life)
	ReasonRevoked = "revoked" // a newer CRL or policy refused it
	ReasonError   = "error"   // the agent could not serve it
	// ReasonLost: the serving process ended without closing it (killed,
	// crashed); the machine's next process wrote the close when it found
	// the session open (relay org orgmachine CloseLost), so Closed is when
	// it was found and In, Out and Path are unknown (zero, none).
	ReasonLost = "lost"
)

// Who is the client as its organisation certificate names it.
type Who struct {
	Name   string   `json:"name"`
	Person string   `json:"person,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Record is one line's rec. Log, Seq, Prev, Machine, Signer, Key and At
// are the log's (Line sets them from its arguments); the rest the
// session's.
type Record struct {
	V       int       `json:"v"`
	Log     string    `json:"log"`
	Seq     uint64    `json:"seq"`
	Prev    string    `json:"prev"`
	Machine string    `json:"machine"`
	Signer  string    `json:"signer"`
	Key     string    `json:"key"`
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Session string    `json:"session"`
	Service string    `json:"service"`
	Who     Who       `json:"who"`
	By      string    `json:"by"`
	Opened  time.Time `json:"opened"`
	Closed  time.Time `json:"closed,omitzero"`
	MS      int64     `json:"ms,omitempty"`
	In      int64     `json:"in,omitempty"`
	Out     int64     `json:"out,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Path    string    `json:"path,omitempty"`
}

// Session is what the serving agent knows of a session at its admission.
type Session struct {
	ID      string
	Service string
	Who     Who
	By      string
	Opened  time.Time
}

// End is what it knows at its end.
type End struct {
	Closed  time.Time
	In, Out int64 // plaintext bytes from and to the client
	Reason  string
	Path    string
}

// Open is s's open record.
func (s Session) Open() Record {
	return Record{Kind: KindOpen, Session: s.ID, Service: s.Service, Who: s.Who, By: s.By, Opened: s.Opened}
}

// Close is s's close record at e.
func (s Session) Close(e End) Record {
	r := s.Open()
	r.Kind, r.Closed, r.MS, r.In, r.Out, r.Reason, r.Path = KindClose, e.Closed, e.Closed.Sub(s.Opened).Milliseconds(), e.In, e.Out, e.Reason, e.Path
	return r
}

const (
	recordContext = "nfltr-audit-v1\x00"
	headContext   = "nfltr-audit-head-v1\x00"
)

// Signing is the log a line goes to and the certified key that signs it.
type Signing struct {
	Log     string
	Seq     uint64 // this line's
	Prev    string // Hash of the line before ("" for seq 1)
	Machine string // the machine's organisation name (its certificate's CN)
	Cert    *x509.Certificate
	Key     ed25519.PrivateKey
	At      time.Time
}

// Line is r signed into a log line (no newline).
func Line(r Record, s Signing) ([]byte, error) {
	r.V, r.Log, r.Seq, r.Prev, r.Machine, r.At = 1, s.Log, s.Seq, s.Prev, s.Machine, s.At.UTC()
	r.Signer, r.Key = hex.EncodeToString(s.Cert.SerialNumber.Bytes()), base64.RawURLEncoding.EncodeToString(s.Key.Public().(ed25519.PublicKey))
	rec, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Rec json.RawMessage `json:"rec"`
		Sig []byte          `json:"sig"`
	}{rec, ed25519.Sign(s.Key, append([]byte(recordContext), rec...))})
}

// Hash is a line's hash, as the next line's Prev names it.
func Hash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// signed is a line's or a head's two members.
type signed struct {
	Rec  json.RawMessage `json:"rec,omitempty"`
	Head json.RawMessage `json:"head,omitempty"`
	Sig  []byte          `json:"sig"`
}

// Parse reads a line's record and checks its signature under the key it
// names (not yet that the key is its machine's: a Checker's Signers).
func Parse(line []byte) (Record, error) {
	var s signed
	if err := json.Unmarshal(line, &s); err != nil || s.Rec == nil {
		return Record{}, errors.New("not an audit line")
	}
	var r Record
	dec := json.NewDecoder(bytes.NewReader(s.Rec))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil || r.V != 1 {
		return Record{}, errors.New("not a version 1 audit record")
	}
	if !verify(r.Key, recordContext, s.Rec, s.Sig) {
		return r, errBadSig
	}
	return r, nil
}

var errBadSig = errors.New("bad signature")

func verify(key, context string, msg, sig []byte) bool {
	pub, err := base64.RawURLEncoding.DecodeString(key)
	return err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, append([]byte(context), msg...), sig)
}

// Head is a machine's signed statement of its log's last line: what the
// keeper posts with its lines, and alone every BeatEvery, so a reader
// sees lines withheld and a machine gone silent.
type Head struct {
	Machine string    `json:"machine"`
	Log     string    `json:"log"`
	Seq     uint64    `json:"seq"`
	Hash    string    `json:"hash"`
	At      time.Time `json:"at"`
	Signer  string    `json:"signer"`
	Key     string    `json:"key"`
}

// SignHead is h signed by s's key (s.Log, Seq, Machine, Cert, At; Prev
// is the last line's hash).
func SignHead(s Signing) ([]byte, error) {
	h := Head{Machine: s.Machine, Log: s.Log, Seq: s.Seq, Hash: s.Prev, At: s.At.UTC(),
		Signer: hex.EncodeToString(s.Cert.SerialNumber.Bytes()), Key: base64.RawURLEncoding.EncodeToString(s.Key.Public().(ed25519.PublicKey))}
	b, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	return json.Marshal(signed{Head: b, Sig: ed25519.Sign(s.Key, append([]byte(headContext), b...))})
}

// ParseHead reads a signed head and checks its signature under the key
// it names.
func ParseHead(msg []byte) (Head, error) {
	var s signed
	var h Head
	if err := json.Unmarshal(msg, &s); err != nil || s.Head == nil || json.Unmarshal(s.Head, &h) != nil {
		return Head{}, errors.New("not a signed audit head")
	}
	if !verify(h.Key, headContext, s.Head, s.Sig) {
		return h, errBadSig
	}
	return h, nil
}

// Signer is what a reader knows of a certificate serial from the issuer's
// own log: the machine it was issued to and its key's fingerprint
// (orgid.KeyFingerprint).
type Signer struct {
	Machine string
	Key     string
}

// Finding is something a reader reports to the operator.
type Finding struct {
	Machine string `json:"machine"`
	Log     string `json:"log,omitempty"`
	Seq     uint64 `json:"seq,omitempty"`
	What    string `json:"what"`
}

func (f Finding) String() string {
	return fmt.Sprintf("machine %s: %s", f.Machine, f.What)
}

// at is where a reader stands in one log of one machine.
type at struct {
	seq  uint64
	hash string
}

// Checker checks lines in the order they were written or received: the
// check of the design's table, one rule for the issuer's intake and every
// later reader. Signers maps a certificate serial (hex) to what the
// issuer issued it for; KeyOf is the fingerprint of a Record's Key
// (orgid.KeyFingerprint of the Ed25519 key), kept out of this package so
// it needs nothing of orgid.
type Checker struct {
	Signers func(serial string) (Signer, bool)
	KeyOf   func(key ed25519.PublicKey) string
	logs    map[string]map[string]*at // machine, log
}

// Seed sets where the checker stands in log of machine (a reader that
// resumes: the issuer's held heads).
func (c *Checker) Seed(machine, log string, seq uint64, hash string) {
	if c.logs == nil {
		c.logs = map[string]map[string]*at{}
	}
	if c.logs[machine] == nil {
		c.logs[machine] = map[string]*at{}
	}
	c.logs[machine][log] = &at{seq: seq, hash: hash}
}

// Logs are the logs of machine the checker has taken lines of.
func (c *Checker) Logs(machine string) []string {
	var ls []string
	for l := range c.logs[machine] {
		ls = append(ls, l)
	}
	return ls
}

// Held is where the checker stands in log of machine: the last seq taken
// and that line's hash.
func (c *Checker) Held(machine, log string) (uint64, string) {
	if a := c.logs[machine][log]; a != nil {
		return a.seq, a.hash
	}
	return 0, ""
}

// Add checks line. ok is whether a reader takes it (the issuer appends
// it): a line that does not parse, is not signed by its machine's
// certified key, or is at or before the seq already taken is refused.
// The findings are what to report, for a taken line too (a gap before
// it, a new log, a broken chain).
func (c *Checker) Add(line []byte) (r Record, ok bool, fs []Finding) {
	r, err := Parse(line)
	if r.Machine == "" && err != nil {
		return r, false, []Finding{{Machine: "?", What: "a line that is not an audit record"}}
	}
	find := func(what string, args ...any) {
		fs = append(fs, Finding{Machine: r.Machine, Log: r.Log, Seq: r.Seq, What: fmt.Sprintf(what, args...)})
	}
	if err != nil {
		find("bad signature at seq %d (edited or forged)", r.Seq)
		return r, false, fs
	}
	if !c.machineKey(r.Signer, r.Key, r.Machine) {
		find("not this machine's key at seq %d (another machine's record, or a key the issuer never certified)", r.Seq)
		return r, false, fs
	}
	if c.logs == nil {
		c.logs = map[string]map[string]*at{}
	}
	logs := c.logs[r.Machine]
	if logs == nil {
		logs = map[string]*at{}
		c.logs[r.Machine] = logs
	}
	a := logs[r.Log]
	if a == nil {
		for l, o := range logs {
			find("new log %s (log %s ended at seq %d)", r.Log, l, o.seq)
		}
		a = &at{}
		logs[r.Log] = a
	}
	switch {
	case r.Seq <= a.seq:
		find("out of order: seq %d after %d (reordered or replayed)", r.Seq, a.seq)
		return r, false, fs
	case r.Seq > a.seq+1:
		find("gap: seq %d..%d missing", a.seq+1, r.Seq-1)
	case r.Prev != a.hash:
		find("chain broken at seq %d (a record removed or inserted before it)", r.Seq)
	}
	a.seq, a.hash = r.Seq, Hash(line)
	return r, true, fs
}

// machineKey: key (base64url) is the key of certificate serial, which the
// issuer issued to machine.
func (c *Checker) machineKey(serial, key, machine string) bool {
	s, ok := c.Signers(serial)
	pub, err := base64.RawURLEncoding.DecodeString(key)
	return ok && err == nil && len(pub) == ed25519.PublicKeySize && s.Machine == machine && s.Key == c.KeyOf(pub)
}

// CheckHead reports what a machine's signed head h says the reader lacks:
// lines withheld (the machine holds more than the reader took). A head
// not signed by its machine's certified key reports only that.
func (c *Checker) CheckHead(msg []byte) (Head, []Finding) {
	h, err := ParseHead(msg)
	switch {
	case err != nil:
		return h, []Finding{{Machine: h.Machine, Log: h.Log, What: "a head with a bad signature"}}
	case !c.machineKey(h.Signer, h.Key, h.Machine):
		return h, []Finding{{Machine: h.Machine, Log: h.Log, What: "a head not signed by this machine's key"}}
	}
	if seq, _ := c.Held(h.Machine, h.Log); seq < h.Seq {
		return h, []Finding{{Machine: h.Machine, Log: h.Log, Seq: h.Seq, What: fmt.Sprintf("withheld: the machine holds seq %d, the issuer %d", h.Seq, seq)}}
	}
	return h, nil
}

// SilentAfter: a machine whose last head is older than this while it has
// sessions open is reported silent (three BeatEvery).
const (
	BeatEvery   = 5 * time.Minute
	ShipEvery   = 30 * time.Second
	SilentAfter = 3 * BeatEvery
)

// Silent is the finding for a machine last heard at heard with open
// sessions open, at now ("" none).
func Silent(machine string, heard time.Time, open int, now time.Time) []Finding {
	if open == 0 || now.Sub(heard) < SilentAfter {
		return nil
	}
	return []Finding{{Machine: machine, What: fmt.Sprintf("silent since %s with %d sessions open", heard.UTC().Format(time.RFC3339), open)}}
}
