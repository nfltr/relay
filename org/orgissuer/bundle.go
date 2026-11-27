// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgissuer

// Moving the organisation to another machine (spec/orgmove/OrgMove.tla,
// spec/proverif/orgmove.pv): the new machine's single-use receive key, the
// old machine's fence and sealed bundle, and the new machine's import.

import (
	"archive/tar"
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nfltr/relay/client/orgid"
	"github.com/nfltr/relay/org/internal/audittrace"
	"github.com/nfltr/relay/org/internal/orgfiles"
	"github.com/nfltr/relay/org/orgpki"
)

// The move's files: the receive key (in nfltr's config directory, beside
// the issuer directory, on the new machine) and the sealed bundle the old
// machine keeps (in its issuer directory) to send again.
const (
	ReceiveKeyFile = "org-move-receive.key"
	SealedFile     = "move.sealed"
	pemReceive     = "NFLTR ORG MOVE RECEIVE KEY"
	receivePrefix  = "nfltr-move1:"
	// MaxBundle bounds a sealed bundle read or opened.
	MaxBundle = 64 << 20
)

// ReceiveKey is the public half of a receive key: what the owner carries
// to the old machine (String), and its fingerprint (the fence names it).
type ReceiveKey struct{ Pub *ecdh.PublicKey }

// String is the receive key as the owner types or pastes it: the X25519
// key and four bytes of its SHA-256, so a mistyped key is refused before
// the old machine fences to a key nobody holds.
func (r ReceiveKey) String() string {
	b := r.Pub.Bytes()
	sum := sha256.Sum256(b)
	return receivePrefix + base64.RawURLEncoding.EncodeToString(append(b, sum[:4]...))
}

// Fingerprint is the key's SPKI fingerprint (orgid.KeyFingerprint).
func (r ReceiveKey) Fingerprint() string { return orgid.KeyFingerprint(r.Pub) }

// Mailbox is the relay mailbox the bundle travels in: named by the receive
// key, which the new machine knows before it knows the organisation.
func (r ReceiveKey) Mailbox() string {
	return "org.move." + strings.TrimPrefix(r.Fingerprint(), "sha256:")[:32]
}

// ParseReceiveKey reads String's form.
func ParseReceiveKey(s string) (ReceiveKey, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), receivePrefix)
	b, err := base64.RawURLEncoding.Strict().DecodeString(rest)
	if !ok || err != nil || len(b) != 36 {
		return ReceiveKey{}, errors.New("not an nfltr move receive key (nfltr-move1:...): copy it again from nfltr org move receive")
	}
	sum := sha256.Sum256(b[:32])
	if !bytes.Equal(sum[:4], b[32:]) {
		return ReceiveKey{}, errors.New("the receive key's check does not match: a character is wrong; copy it again")
	}
	pub, err := ecdh.X25519().NewPublicKey(b[:32])
	if err != nil {
		return ReceiveKey{}, err
	}
	return ReceiveKey{Pub: pub}, nil
}

// LoadReceiveKey is the receive key's private half at path, made (0600)
// when none is there: it survives a restart of the new machine until its
// import deletes it (OrgMove.tla ephemeral-receive-key).
func LoadReceiveKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- nfltr's own config file
	if errors.Is(err, os.ErrNotExist) {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := orgfiles.WriteNew(path, pem.EncodeToMemory(&pem.Block{Type: pemReceive, Bytes: k.Bytes()}), 0o600); err != nil {
			return nil, err
		}
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != pemReceive {
		return nil, fmt.Errorf("%s is not a move receive key", path)
	}
	return ecdh.X25519().NewPrivateKey(b.Bytes)
}

func moveInfo(fp string) []byte { return []byte("nfltr-org-move-v1\x00" + fp) }

func hpkeSuite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.ChaCha20Poly1305() }

// The bundle's members, by their path under nfltr's config directory: the
// issuer directory's log, key, CRL and answers spool, and its session
// audit (auditFiles). Nothing else is
// taken from it or written by an import:
//   - not the root primary (a file root's root-<label>.key; a Secure
//     Enclave root never leaves its Mac anyway): the root stays with its
//     owner, so a compromise of the issuer's new machine costs the issuer
//     only; the root's holder renews the issuer from there (orgpki
//     renew.go);
//   - not the machine-key root and store nfltr keeps beside it
//     (a2a-root.key, a2a-machines.json), which its other services on this
//     machine use and which stay with them; an issuer without them enrols
//     machines without a machine key.
//
// The new machine refuses a bundle with any other member (an older
// nfltr's, which carried both).
func bundleMember(name string) bool {
	switch name {
	case "org/" + LogFile, "org/" + IssuerKeyFile, "org/" + CRLFile:
		return true
	}
	if dir, base := path.Split(name); dir == "org/" && slices.Contains(auditFiles, base) {
		return true
	}
	dir, base := path.Split(name)
	return dir == "org/answers/" && base != "" && !strings.HasPrefix(base, ".")
}

// Send is the old machine's side, `nfltr org move send`: under the issuer
// directory's lock it signs a fresh CRL (the move then has its whole
// life), commits the fence naming to, and seals the bundle to to, kept as
// SealedFile. Run again it returns the same sealed bundle; it refuses
// another receive key than the fence names.
func Send(configDir string, to ReceiveKey, now time.Time) ([]byte, error) {
	s, err := Lock(Dir(configDir))
	if err != nil {
		return nil, err
	}
	defer s.Unlock()
	iss, err := s.open()
	if err != nil {
		return nil, err
	}
	fp := to.Fingerprint()
	switch moved := iss.Moved(); {
	case moved == "":
		crl, err := iss.CRL(now)
		if err == nil {
			err = s.WriteCRL(crl, iss.Cert())
		}
		if err == nil {
			err = iss.Fence(fp, now)
		}
		if err != nil {
			return nil, err
		}
		audittrace.Line(map[string]any{"ev": "fence", "h": Dir(configDir)}) // MoveAudit.tla Fence
		_ = os.Remove(s.Path(SealedFile))
	case moved != fp:
		return nil, fmt.Errorf("%w: the fence names receive key %s, not this one (%s); a move goes to the one key it was fenced for", orgpki.ErrMoved, moved, fp)
	default:
		if sealed, err := os.ReadFile(s.Path(SealedFile)); err == nil { // #nosec G304 -- the issuer's own file
			audittrace.Line(map[string]any{"ev": "send", "h": Dir(configDir)})
			return sealed, nil
		}
	}
	plain, err := s.bundle(configDir)
	if err != nil {
		return nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(to.Pub)
	if err != nil {
		return nil, err
	}
	kdf, aead := hpkeSuite()
	sealed, err := hpke.Seal(pk, kdf, aead, moveInfo(fp), plain)
	if err != nil {
		return nil, err
	}
	if err := orgfiles.Write(s.Path(SealedFile), sealed, 0o600); err != nil {
		return nil, err
	}
	orgpki.TraceSend(iss.OrgID(), fp, iss.Head())
	audittrace.Line(map[string]any{"ev": "send", "h": Dir(configDir)}) // Send: the bundle holds the sessions files
	return sealed, nil
}

// Restore is a restore from a backup's first step, `nfltr org move send
// --restored` on the copy restore-secrets set aside (spec/orgmove/OrgMove.tla
// Revive): under the directory's lock the copy takes the newest of crl,
// the CRL the relay holds (orgenrol.PublishedRevocationList), fleet,
// members' CRLs the operator gives (a member's crl.der), and this
// machine's own member CRL when it holds one of this issuer
// (orgid.Dir(configDir)'s crl.der): a relay withholding the newest CRL
// is outvoted (OrgMove.tla OfferAny; lane SECFIX2, review S8;
// orgpki.Issuer.Restore). Send then signs the CRL above it and fences. It
// returns the Number of the CRL taken.
func Restore(configDir string, crl []byte, now time.Time, fleet ...[]byte) (int64, error) {
	s, err := Lock(Dir(configDir))
	if err != nil {
		return 0, err
	}
	defer s.Unlock()
	iss, err := s.Open()
	if err != nil {
		return 0, err
	}
	if own, err := os.ReadFile(filepath.Join(orgid.Dir(configDir), orgid.CRLFile)); err == nil { // #nosec G304 -- this machine's own member directory
		if c, err := x509.ParseRevocationList(own); err == nil && c.CheckSignatureFrom(iss.Cert()) == nil {
			fleet = append(fleet, own)
		}
	}
	if err := iss.Restore(crl, now, fleet...); err != nil {
		return 0, err
	}
	n, _ := iss.LastCRL()
	return n, nil
}

// bundle is the tar of the bundle's members.
func (s *Store) bundle(configDir string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.WalkDir(configDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(configDir, p)
		name := filepath.ToSlash(rel)
		if d.IsDir() {
			if p != configDir && name != "org" && name != "org/answers" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !bundleMember(name) {
			return nil
		}
		data, err := os.ReadFile(p) // #nosec G304 G122 -- a member of the bundle, in nfltr's config directory (the owner's own; no other user writes there)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Imported is what Import made: the organisation, as it now serves here.
type Imported struct {
	OrgID, Root string
	CRL         int64
}

// Import is the new machine's side, `nfltr org move receive`: it opens
// sealed with the receive key at keyPath and takes it only when its log
// verifies, its root is the one pinned (rootPin: the fingerprint every
// machine of the organisation has), its issuer key is the log's issuer's,
// and its last line is the fence naming this receive key. It writes the
// members under configDir, the log last with the arrival appended, then
// deletes the receive key: the key opens one bundle once
// (OrgMove.tla reusable-receive-key).
func Import(configDir, keyPath string, sealed []byte, rootPin string, now time.Time) (Imported, error) {
	key, err := LoadReceiveKey(keyPath)
	if err != nil {
		return Imported{}, err
	}
	fp := ReceiveKey{Pub: key.PublicKey()}.Fingerprint()
	members, err := openBundle(key, fp, sealed)
	if err != nil {
		return Imported{}, err
	}
	lines := splitLines(members["org/"+LogFile])
	ik, err := ReadKey(members["org/"+IssuerKeyFile], PEMIssuer)
	if err != nil {
		return Imported{}, fmt.Errorf("the bundle's issuer key: %w", err)
	}
	var arrival []byte
	iss, err := orgpki.Open(lines, ik, func(l []byte) error { arrival = l; return nil })
	if err != nil {
		return Imported{}, err
	}
	prev := iss.Head()
	if got := orgid.Fingerprint(iss.Root()); got != rootPin {
		return Imported{}, fmt.Errorf("the bundle is organisation %s of root %s, not of the root %s given: refused", iss.OrgID(), got, rootPin)
	}
	if err := iss.Arrive(fp, now); err != nil { // the log ends in the fence naming this key
		return Imported{}, err
	}
	if err := placeMembers(configDir, members, fp); err != nil {
		return Imported{}, err
	}
	log := append(bytes.Join(append(lines, arrival), []byte("\n")), '\n')
	if err := orgfiles.WriteNew(filepath.Join(Dir(configDir), LogFile), log, 0o600); err != nil {
		return Imported{}, err
	}
	orgpki.TraceImport(iss.OrgID(), fp, prev, iss.Head())
	audittrace.Line(map[string]any{"ev": "import", "h": Dir(configDir)}) // Import
	if err := os.Remove(keyPath); err != nil {
		return Imported{}, fmt.Errorf("imported, but the receive key is not deleted (delete %s): %w", keyPath, err)
	}
	n, _ := iss.LastCRL()
	return Imported{OrgID: iss.OrgID(), Root: orgid.Fingerprint(iss.Root()), CRL: n}, nil
}

// openBundle opens a bundle sealed to key and reads its members.
func openBundle(key *ecdh.PrivateKey, fp string, sealed []byte) (map[string][]byte, error) {
	sk, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, err
	}
	kdf, aead := hpkeSuite()
	plain, err := hpke.Open(sk, kdf, aead, moveInfo(fp), sealed)
	if err != nil {
		return nil, errors.New("the bundle does not open with this machine's receive key: it was sealed to another")
	}
	members := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(plain))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg || !bundleMember(h.Name) || members[h.Name] != nil {
			return nil, fmt.Errorf("the bundle holds %q: not a member of an organisation's move", h.Name)
		}
		if members[h.Name], err = io.ReadAll(io.LimitReader(tr, MaxBundle)); err != nil {
			return nil, err
		}
	}
	for _, need := range []string{"org/" + LogFile, "org/" + IssuerKeyFile} {
		if members[need] == nil {
			return nil, fmt.Errorf("the bundle holds no %s", need)
		}
	}
	return members, nil
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	for l := range bytes.SplitSeq(data, []byte("\n")) {
		if len(bytes.TrimSpace(l)) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// placeMembers writes every member but the log. The issuer directory must
// hold no organisation, or the tombstone of this one's earlier move from
// here (nfltr org move finish ran: no issuer key; or the bundle's log
// continues the tombstone's, a move back, whose moved keys it deletes),
// whose issuer files (tombstoneFiles) are set aside in <dir>.moved-<unix>;
// the rest of the directory stays: the file root (the organisation comes
// back to it) and the machine's own membership (machine/, orgid.Dir), for
// the issuer's machine may be a member too. A file already there is kept
// only when it holds the member's bytes (an import run again after a
// crash).
func placeMembers(configDir string, members map[string][]byte, fp string) error {
	dir := Dir(configDir)
	if Exists(dir) {
		s := &Store{dir: dir}
		lines, err := s.Lines()
		if err != nil {
			return err
		}
		if e, ok := lastEntry(lines); !ok || e.Act != orgpki.ActMoved {
			return errors.New("this machine holds an organisation already (nfltr org status)")
		}
		if _, err := os.Stat(s.Path(IssuerKeyFile)); err == nil {
			// A move back: the bundle's log continues this tombstone's (the
			// organisation went from here and comes back), so its issuer
			// key supersedes the moved keys here, which go (spec/orgmove/
			// OrgHolds.tla Import; mutant refuse-own-tombstone). Any other
			// bundle waits for nfltr org move finish.
			if !extendsLog(splitLines(members["org/"+LogFile]), lines) {
				return errors.New("this machine holds a moved organisation's keys and the bundle does not continue its log: nfltr org move finish first")
			}
			for _, f := range []string{IssuerKeyFile, IssuerKeyFile + ".new", SealedFile} {
				if err := os.Remove(s.Path(f)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
		aside := fmt.Sprintf("%s.moved-%d", dir, time.Now().Unix())
		if err := os.MkdirAll(aside, 0o700); err != nil { // nosemgrep: incorrect-default-permission -- owner-only directory
			return err
		}
		for _, f := range tombstoneFiles {
			if err := os.Rename(s.Path(f), filepath.Join(aside, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	for name, data := range members {
		if name == "org/"+LogFile {
			continue
		}
		p := filepath.Join(configDir, filepath.FromSlash(name))
		if have, err := os.ReadFile(p); err == nil && !bytes.Equal(have, data) { // #nosec G304 -- a member's path under nfltr's config directory
			return fmt.Errorf("%s exists with other content: not imported", p)
		}
	}
	for name, data := range members {
		if name == "org/"+LogFile {
			continue
		}
		p := filepath.Join(configDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil { // nosemgrep: incorrect-default-permission -- owner-only directory
			return err
		}
		if err := orgfiles.Write(p, data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// tombstoneFiles are the files the issuer wrote in its directory that a
// receive sets aside, the log last (until it goes, Exists holds and an
// import run again after a crash sets the rest aside). The issuer keys and
// the sealed bundle are gone by then (finish, or the move back above).
// "answers" and "publish-failing.json" are orgenrol's spool and publish
// state (its spoolDir, publishFailingFile).
var tombstoneFiles = append(append([]string{"answers", CRLFile, KRLFile, SealedFile, "publish-failing.json"}, auditFiles...), LogFile)

// auditFiles are orgenrol's session audit files (SessionsFile, HeadsFile,
// SinkCursorFile, ConfigFile: the lines the machines were answered for,
// where the issuer stands per machine, the sink's cursor and setting).
// They are the issuer's state, so they move with it (spec/MoveAudit.tla
// AckedHeld; mutant bundle-no-sessions): a machine sends a line once its
// answer came, and the new issuer would report the lines before as a gap.
var auditFiles = []string{"sessions.jsonl", "sessions-heads.json", "sessions.sink", "config.json"}

// extendsLog reports whether log begins with every line of prefix: the
// bundle's log (verified by Import) continues this machine's tombstone.
func extendsLog(log, prefix [][]byte) bool {
	if len(prefix) == 0 || len(prefix) > len(log) {
		return false
	}
	for i, l := range prefix {
		if !bytes.Equal(l, log[i]) {
			return false
		}
	}
	return true
}

// lastEntry is a log's last line, unverified (a fence is read before its
// key, which may be gone).
func lastEntry(lines [][]byte) (orgpki.Entry, bool) {
	var e orgpki.Entry
	if len(lines) == 0 || json.Unmarshal(lines[len(lines)-1], &e) != nil {
		return e, false
	}
	return e, true
}

// Finish is the old machine's last step, `nfltr org move finish`: it
// deletes the key the move carried away (the issuer key) and the sealed
// bundle, and keeps the fenced log as the tombstone `nfltr org status`
// reads and `nfltr org issuer sign` pins; the root and the machine-key
// root and store stay (they did not move). Only after a fence.
func Finish(configDir string) ([]string, error) {
	s, err := Lock(Dir(configDir))
	if err != nil {
		return nil, err
	}
	defer s.Unlock()
	lines, err := s.Lines()
	if err != nil {
		return nil, err
	}
	if e, ok := lastEntry(lines); !ok || e.Act != orgpki.ActMoved {
		return nil, errors.New("this organisation has not moved (nfltr org move send fences it first)")
	}
	var removed []string
	rm := func(p string) error {
		if err := os.Remove(p); err == nil {
			removed = append(removed, p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	for _, p := range []string{s.Path(IssuerKeyFile), s.Path(IssuerKeyFile + ".new"), s.Path(SealedFile)} {
		if err := rm(p); err != nil {
			return removed, err
		}
	}
	return removed, nil
}
