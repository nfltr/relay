// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgissuer

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nfltr/relay/org/orgpki"
	"github.com/nfltr/relay/client/orgid"
)

// Moving the organisation (spec/orgmove/OrgMove.tla and its README's
// invariants, spec/proverif/orgmove.pv).

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// newOrgConfig makes an organisation in a config directory as nfltr org
// init does (a file root's file stands in as bytes), with an answer in its
// spool and the machine-key root and store beside it. It returns the
// directory and the root's fingerprint.
func newOrgConfig(t *testing.T) (string, string) {
	t.Helper()
	conf := t.TempDir()
	rk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, rec, _ := ed25519.GenerateKey(rand.Reader)
	_, ik, _ := ed25519.GenerateKey(rand.Reader)
	id, err := orgpki.OrgID(rk.Public())
	if err != nil {
		t.Fatal(err)
	}
	root, err := orgpki.NewRoot(rk, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	recCert, err := orgpki.NewRecovery(rec, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	ic, err := orgpki.CertifyIssuer(root, rk, ik.Public().(ed25519.PublicKey), []string{"web"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := orgpki.Genesis(root, recCert, "org", orgpki.RootFile, ic, t0)
	if err != nil {
		t.Fatal(err)
	}
	dir := Dir(conf)
	files := map[string][]byte{
		filepath.Join(dir, LogFile):         append(bytes.Join(lines, []byte("\n")), '\n'),
		filepath.Join(dir, "answers", "a1"): []byte(`{"id":"a1"}`),
		filepath.Join(dir, "root-org.key"):  []byte("sealed root"),
		filepath.Join(conf, a2aRootKeyFile): []byte("a2a root"),
		filepath.Join(conf, a2aStoreFile):   []byte(`{"machines":[]}`),
	}
	for p, data := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteKey(filepath.Join(dir, IssuerKeyFile), PEMIssuer, ik, true); err != nil {
		t.Fatal(err)
	}
	return conf, orgid.Fingerprint(root)
}

// receiver is a new machine: its config directory and receive key.
func receiver(t *testing.T) (conf, keyPath string, rk ReceiveKey) {
	t.Helper()
	conf = t.TempDir()
	keyPath = filepath.Join(conf, ReceiveKeyFile)
	k, err := LoadReceiveKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return conf, keyPath, ReceiveKey{Pub: k.PublicKey()}
}

func openStore(t *testing.T, conf string) (*Store, error) {
	t.Helper()
	s, err := Lock(Dir(conf))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Unlock()
	_, err = s.Open()
	return s, err
}

// The whole move: the new machine serves the same organisation, the old
// one refuses (ErrMoved), every member arrived (the spool too: mutant
// no-spool-in-bundle), and the CRL Number continues.
func TestMoveRoundTrip(t *testing.T) {
	old, pin := newOrgConfig(t)
	conf, keyPath, rk := receiver(t)
	parsed, err := ParseReceiveKey(rk.String())
	if err != nil || !parsed.Pub.Equal(rk.Pub) {
		t.Fatalf("the receive key does not parse back: %v", err)
	}
	sealed, err := Send(old, parsed, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(t, old); !errors.Is(err, orgpki.ErrMoved) {
		t.Fatalf("the old machine after send: %v, want ErrMoved", err)
	}
	im, err := Import(conf, keyPath, sealed, pin, t0)
	if err != nil {
		t.Fatal(err)
	}
	if im.CRL != 1 {
		t.Fatalf("CRL #%d imported, want #1 (signed at the fence)", im.CRL)
	}
	for _, rel := range []string{"org/answers/a1", "org/" + IssuerKeyFile, "org/" + CRLFile} {
		want, _ := os.ReadFile(filepath.Join(old, rel))
		got, err := os.ReadFile(filepath.Join(conf, rel))
		if err != nil || (want != nil && !bytes.Equal(got, want)) {
			t.Errorf("%s did not arrive intact: %v", rel, err)
		}
	}
	s, err := Lock(Dir(conf))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Unlock()
	iss, err := s.Open()
	if err != nil {
		t.Fatalf("the new machine does not serve: %v", err)
	}
	if _, err := iss.CRL(t0); err != nil {
		t.Fatal(err)
	}
	if n, _ := iss.LastCRL(); n != 2 {
		t.Fatalf("CRL #%d after the move, want #2", n)
	}
	lines, _ := s.Lines()
	if _, _, err := orgpki.VerifyLog(lines); err != nil {
		t.Fatalf("the moved log: %v", err)
	}
	removed, err := Finish(old)
	if err != nil || len(removed) != 2 {
		t.Fatalf("finish removed %v: %v", removed, err)
	}
	if _, err := openStore(t, old); !errors.Is(err, orgpki.ErrMoved) {
		t.Fatalf("the tombstone: %v, want ErrMoved", err)
	}
}

// OrgMove.tla reusable-receive-key: the receive key opens one bundle once.
// The new machine's disk lost after its import, the same bundle (replayed
// by the relay, or kept on a stick) does not import again.
func TestReceiveKeyIsSingleUse(t *testing.T) {
	old, pin := newOrgConfig(t)
	conf, keyPath, rk := receiver(t)
	sealed, err := Send(old, rk, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(conf, keyPath, sealed, pin, t0); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{Dir(conf)} {
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Import(conf, keyPath, sealed, pin, t0); err == nil {
		t.Fatal("the same bundle imported twice")
	}
}

// OrgMove.tla ephemeral-receive-key: the receive key is a file; the new
// machine restarted before its import still opens the bundle.
func TestReceiveKeySurvivesARestart(t *testing.T) {
	old, pin := newOrgConfig(t)
	conf, keyPath, rk := receiver(t)
	again, err := LoadReceiveKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !again.PublicKey().Equal(rk.Pub) {
		t.Fatal("a restart made a new receive key")
	}
	sealed, err := Send(old, rk, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(conf, keyPath, sealed, pin, t0); err != nil {
		t.Fatal(err)
	}
}

// OrgMove.tla no-resend, fence-names-no-recipient: send again re-sends the
// same sealed bundle, which imports; another receive key is refused.
func TestMoveResendsUntilImported(t *testing.T) {
	old, pin := newOrgConfig(t)
	conf, keyPath, rk := receiver(t)
	first, err := Send(old, rk, t0)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Send(old, rk, t0.Add(time.Minute))
	if err != nil || !bytes.Equal(first, again) {
		t.Fatalf("the second send: %v (same bytes %v)", err, bytes.Equal(first, again))
	}
	_, _, other := receiver(t)
	if _, err := Send(old, other, t0); !errors.Is(err, orgpki.ErrMoved) {
		t.Fatalf("a send to another receive key: %v, want ErrMoved", err)
	}
	if _, err := Import(conf, keyPath, again, pin, t0); err != nil {
		t.Fatal(err)
	}
}

const moveModel = "../../spec/proverif/orgmove.pv"

// moveBindings: each row makes the bundle the new machine (receive key
// rk, root pin) receives from what an attacker owning the relay can make,
// changing just that binding of the honest move.
var moveBindings = map[string]func(t *testing.T, old string, rk ReceiveKey) []byte{
	// Sealed to another receive key than this machine's.
	"move.rcpt": func(t *testing.T, old string, _ ReceiveKey) []byte {
		_, _, other := receiver(t)
		sealed, err := Send(old, other, t0)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	},
	// An honest move of another organisation (the attacker's own), to
	// this receive key.
	"move.root": func(t *testing.T, _ string, rk ReceiveKey) []byte {
		evil, _ := newOrgConfig(t)
		sealed, err := Send(evil, rk, t0)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	},
	// The organisation's bundle fenced for another key, sealed to this one.
	"move.fence": func(t *testing.T, old string, rk ReceiveKey) []byte {
		_, _, other := receiver(t)
		if _, err := Send(old, other, t0); err != nil {
			t.Fatal(err)
		}
		s, err := Lock(Dir(old))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Unlock()
		plain, err := s.bundle(old)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := hpke.NewDHKEMPublicKey(rk.Pub)
		if err != nil {
			t.Fatal(err)
		}
		kdf, aead := hpkeSuite()
		sealed, err := hpke.Seal(pk, kdf, aead, moveInfo(rk.Fingerprint()), plain)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	},
}

// TestOrgMoveModelBindings runs every row (make spec-bindings), and fails
// when orgmove.pv's BIND:move.* ids and the rows differ (BIND:renew.* are
// orgpki's TestIssuerRenewalModelBindings).
func TestOrgMoveModelBindings(t *testing.T) {
	src, err := os.ReadFile(moveModel)
	if err != nil {
		t.Fatal(err)
	}
	var model, rows []string
	for _, m := range regexp.MustCompile(`BIND:(move\.[a-z0-9.]+)`).FindAllSubmatch(src, -1) {
		model = append(model, string(m[1]))
	}
	for id := range moveBindings {
		rows = append(rows, id)
	}
	slices.Sort(model)
	slices.Sort(rows)
	if !slices.Equal(model, rows) {
		t.Fatalf("%s BIND ids %v, rows %v: each binding of the model needs one row", moveModel, model, rows)
	}
	for _, id := range rows {
		t.Run(id, func(t *testing.T) {
			old, pin := newOrgConfig(t)
			conf, keyPath, rk := receiver(t)
			sealed := moveBindings[id](t, old, rk)
			if _, err := Import(conf, keyPath, sealed, pin, t0); err == nil {
				t.Fatalf("the bundle with %s changed was imported; want refused", id)
			}
			if Exists(Dir(conf)) {
				t.Fatal("a refused bundle left an organisation behind")
			}
		})
	}
	// The honest move, as the rows start from it, imports.
	old, pin := newOrgConfig(t)
	conf, keyPath, rk := receiver(t)
	sealed, err := Send(old, rk, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(conf, keyPath, sealed, pin, t0); err != nil {
		t.Fatalf("the honest move: %v", err)
	}
}

// The machine-key root and store beside the issuer are not the
// organisation's: a move neither carries them nor deletes them on the old
// machine, where other services use them, and the new machine imports
// no bundle that holds them (mutants a2a-root-moves, finish-deletes-a2a-root).
func TestBundleCarriesNoA2ARoot(t *testing.T) {
	old, pin := newOrgConfig(t)
	conf, keyPath, rk := receiver(t)
	sealed, err := Send(old, rk, t0)
	if err != nil {
		t.Fatal(err)
	}
	k, err := LoadReceiveKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	members, err := openBundle(k, rk.Fingerprint(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{a2aRootKeyFile, a2aStoreFile} {
		if members[f] != nil {
			t.Errorf("the bundle carries the machine-key file %s", f)
		}
	}
	if _, err := Import(conf, keyPath, sealed, pin, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := Finish(old); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{a2aRootKeyFile, a2aStoreFile} {
		if exists(filepath.Join(conf, f)) {
			t.Errorf("the import wrote %s", f)
		}
		if !exists(filepath.Join(old, f)) {
			t.Errorf("finish deleted the machine-key file %s on the old machine", f)
		}
	}
	// A bundle that holds the machine-key root (an older nfltr's) is not imported.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range map[string][]byte{"org/" + LogFile: []byte("{}\n"), "org/" + IssuerKeyFile: []byte("k"), a2aRootKeyFile: []byte("a2a root")} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	k2, err := LoadReceiveKey(filepath.Join(t.TempDir(), ReceiveKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	rk2 := ReceiveKey{Pub: k2.PublicKey()}
	pk, _ := hpke.NewDHKEMPublicKey(rk2.Pub)
	kdf, aead := hpkeSuite()
	bad, err := hpke.Seal(pk, kdf, aead, moveInfo(rk2.Fingerprint()), buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openBundle(k2, rk2.Fingerprint(), bad); err == nil || !strings.Contains(err.Error(), a2aRootKeyFile) {
		t.Fatalf("a bundle holding the machine-key root: %v, want refused naming it", err)
	}
}

// The root stays with its owner (orgmove.pv query 2, mutants root-moves,
// finish-deletes-root): the bundle holds the log, the issuer key, the CRL
// and the spool only (nothing of a file root, and a Secure Enclave root has
// nothing on disk), finish keeps the root file, the new machine imports no
// bundle that holds one, and when the organisation comes back the root
// file is where it was.
func TestRootStaysWithItsOwner(t *testing.T) {
	old, pin := newOrgConfig(t)
	conf, keyPath, rk := receiver(t)
	sealed, err := Send(old, rk, t0)
	if err != nil {
		t.Fatal(err)
	}
	k, err := LoadReceiveKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	members, err := openBundle(k, rk.Fingerprint(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	for name := range members {
		if !slices.Contains([]string{"org/" + LogFile, "org/" + IssuerKeyFile, "org/" + CRLFile, "org/answers/a1"}, name) {
			t.Errorf("the bundle carries %s", name)
		}
	}
	if _, err := Import(conf, keyPath, sealed, pin, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(Dir(conf), "root-org.key")); err == nil {
		t.Error("the import wrote the root file")
	}
	if _, err := Finish(old); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(Dir(old), "root-org.key")); err != nil || string(got) != "sealed root" {
		t.Fatalf("finish deleted the root file on the old machine: %v", err)
	}

	// Back: the organisation arrives where its root is; the root file stays
	// in the issuer directory.
	back := filepath.Join(old, ReceiveKeyFile)
	bk, err := LoadReceiveKey(back)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = Send(conf, ReceiveKey{Pub: bk.PublicKey()}, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(old, back, sealed, pin, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(Dir(old), "root-org.key")); err != nil || string(got) != "sealed root" {
		t.Fatalf("the root file after the organisation came back: %v", err)
	}
	if _, err := openStore(t, old); err != nil {
		t.Fatalf("the organisation back on the root's machine: %v", err)
	}

	// A bundle that holds a root file (an older nfltr's) is not imported.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range map[string][]byte{"org/" + LogFile: []byte("{}\n"), "org/" + IssuerKeyFile: []byte("k"), "org/root-org.key": []byte("sealed root")} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	k2, err := LoadReceiveKey(filepath.Join(t.TempDir(), ReceiveKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	rk2 := ReceiveKey{Pub: k2.PublicKey()}
	pk, _ := hpke.NewDHKEMPublicKey(rk2.Pub)
	kdf, aead := hpkeSuite()
	bad, err := hpke.Seal(pk, kdf, aead, moveInfo(rk2.Fingerprint()), buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openBundle(k2, rk2.Fingerprint(), bad); err == nil || !strings.Contains(err.Error(), "root-org.key") {
		t.Fatalf("a bundle holding the root: %v, want refused naming it", err)
	}
}

// TestMoveBackReplacesTheTombstone (spec/orgmove/OrgHolds.tla Import,
// mutant refuse-own-tombstone; the 2026-11-15 production rollback): the
// new machine never published, so finish on the old one refuses; the
// organisation comes back with its moved keys still there. The import
// takes a bundle whose log continues the tombstone's and deletes the
// moved keys; one whose log does not continue it is refused (before: any
// bundle was refused until the keys were deleted by hand).
func TestMoveBackReplacesTheTombstone(t *testing.T) {
	old, pin := newOrgConfig(t)
	conf, keyPath, rk := receiver(t)
	sealed, err := Send(old, rk, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(conf, keyPath, sealed, pin, t0); err != nil {
		t.Fatal(err)
	}
	back := filepath.Join(old, ReceiveKeyFile)
	bk, err := LoadReceiveKey(back)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = Send(conf, ReceiveKey{Pub: bk.PublicKey()}, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// A tombstone the bundle does not continue keeps its keys.
	logPath := filepath.Join(Dir(old), LogFile)
	orig, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, append([]byte("{}\n"), orig...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(old, back, sealed, pin, t0.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "does not continue its log") {
		t.Fatalf("a bundle that does not continue the tombstone: %v", err)
	}
	if err := os.WriteFile(logPath, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	im, err := Import(old, back, sealed, pin, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("the move back: %v", err)
	}
	if _, err := openStore(t, old); err != nil {
		t.Fatalf("the organisation back on the old machine: %v", err)
	}
	if im.CRL < 2 {
		t.Errorf("CRL #%d after the move back", im.CRL)
	}
	aside, _ := filepath.Glob(Dir(old) + ".moved-*")
	for _, d := range aside {
		for _, f := range []string{IssuerKeyFile, SealedFile} {
			if _, err := os.Stat(filepath.Join(d, f)); err == nil {
				t.Errorf("the set-aside tombstone keeps %s", f)
			}
		}
	}
}

// The organisation coming back to a machine that is also a member of it
// keeps that machine's membership (mutant receive-drops-membership): the
// tombstone set aside is the issuer's files only; machine/ (orgid.Dir) and
// any file the issuer did not write stay where they were.
func TestReceiveKeepsTheMachinesMembership(t *testing.T) {
	old, pin := newOrgConfig(t)
	own := map[string][]byte{
		filepath.Join(Dir(old), "machine", "cert.pem"): []byte("membership"),
		filepath.Join(Dir(old), "machine", "key.pem"):  []byte("machine key"),
		filepath.Join(Dir(old), "not-the-issuers"):     []byte("kept"),
	}
	for p, data := range own {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	conf, keyPath, rk := receiver(t)
	sealed, err := Send(old, rk, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(conf, keyPath, sealed, pin, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := Finish(old); err != nil {
		t.Fatal(err)
	}
	back := filepath.Join(old, ReceiveKeyFile)
	bk, err := LoadReceiveKey(back)
	if err != nil {
		t.Fatal(err)
	}
	if sealed, err = Send(conf, ReceiveKey{Pub: bk.PublicKey()}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(old, back, sealed, pin, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for p, want := range own {
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s after the organisation came back: %q, %v", p, got, err)
		}
	}
	if _, err := openStore(t, old); err != nil {
		t.Fatalf("the organisation back: %v", err)
	}
	aside, _ := filepath.Glob(Dir(old) + ".moved-*")
	if len(aside) != 1 || !exists(filepath.Join(aside[0], LogFile)) {
		t.Fatalf("the tombstone set aside: %v", aside)
	}
}

// The machine-key root and store beside the issuer's directory, which a
// move must leave behind.
const (
	a2aRootKeyFile = "a2a-root.key"
	a2aStoreFile   = "a2a-machines.json"
)

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
