// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package orgissuer is the organisation issuer's directory on the owner's
// machine: its audit log
// (the issuer's only state, replayed by orgpki.Open), its key and its
// newest CRL, under one file lock for every act. `nfltr org`, the
// issuer's mailbox service (Serve) and an account-revocation tie-in
// (RevokeMachines) all go through it.
package orgissuer

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nfltr/relay/org/internal/orgfiles"
	"github.com/nfltr/relay/org/orgpki"
)

// The files of the issuer's directory, and the PEM kinds of its keys.
const (
	LogFile       = "audit.jsonl"
	IssuerKeyFile = "issuer.key"
	CRLFile       = "crl.der"
	KRLFile       = "revoked-hosts.krl" // the CRL's OpenSSH KRL (orgpki.HostKRL), 0644
	PEMIssuer     = "NFLTR ORG ISSUER KEY"
	PEMRecovery   = "NFLTR ORG RECOVERY KEY"
)

// Dir is the issuer's directory under nfltr's config directory.
func Dir(configDir string) string { return filepath.Join(configDir, "org") }

// Store is the issuer's directory, locked.
type Store struct {
	dir    string
	unlock func()
}

// Lock takes the directory's lock (creating it), waiting for another
// holder.
func Lock(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil { // nosemgrep: incorrect-default-permission -- a directory needs x; 0o700 is owner-only
		return nil, err
	}
	unlock, err := orgfiles.Lock(filepath.Join(dir, "lock"))
	if err != nil {
		return nil, err
	}
	return &Store{dir: dir, unlock: unlock}, nil
}

// Unlock releases the lock.
func (s *Store) Unlock() { s.unlock() }

// Path is a file of the directory.
func (s *Store) Path(name string) string { return filepath.Join(s.dir, name) }

// Exists reports whether the directory holds an organisation.
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, LogFile))
	return err == nil
}

// Lines is the audit log's lines.
func (s *Store) Lines() ([][]byte, error) {
	f, err := os.Open(s.Path(LogFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("no organisation on this machine: nfltr org init")
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			out = append(out, append([]byte(nil), sc.Bytes()...))
		}
	}
	return out, sc.Err()
}

// Sink appends one line and syncs it before the issuer acts on it.
func (s *Store) Sink(line []byte) error {
	f, err := os.OpenFile(s.Path(LogFile), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// WriteKey writes an Ed25519 key as PKCS#8 PEM of kind, 0600; fresh: never
// over a file.
func WriteKey(path, kind string, key ed25519.PrivateKey, fresh bool) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	if fresh {
		return orgfiles.WriteNew(path, data, 0o600)
	}
	return orgfiles.Write(path, data, 0o600)
}

// ReadKey parses WriteKey's PEM of kind.
func ReadKey(data []byte, kind string) (ed25519.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != kind {
		return nil, fmt.Errorf("not a %s", strings.ToLower(kind))
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	ek, ok := k.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, fmt.Errorf("not an Ed25519 %s", strings.ToLower(kind))
	}
	return ek, nil
}

// Open replays the log under the issuer's key. A rotation that stopped
// after its log lines left the new key in issuer.key.new: taken here when
// it is the one the log names. A log that ends in a move's fence is
// orgpki.ErrMoved: this machine's issuer acts no more (bundle.go).
func (s *Store) Open() (*orgpki.Issuer, error) {
	iss, err := s.open()
	if err == nil && iss.Moved() != "" {
		err = fmt.Errorf("%w (fenced for receive key %s): this machine's copy is a tombstone; nfltr org status on the new machine", orgpki.ErrMoved, iss.Moved())
	}
	if err != nil {
		return nil, err
	}
	return iss, nil
}

func (s *Store) open() (*orgpki.Issuer, error) {
	lines, err := s.Lines()
	if err != nil {
		return nil, err
	}
	if e, ok := lastEntry(lines); ok && e.Act == orgpki.ActMoved {
		if _, err := os.Stat(s.Path(IssuerKeyFile)); errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w (fenced for receive key %s; its keys deleted by nfltr org move finish)", orgpki.ErrMoved, e.Key)
		}
	}
	var errs []error
	for _, name := range []string{IssuerKeyFile, IssuerKeyFile + ".new"} {
		data, err := os.ReadFile(s.Path(name)) // #nosec G304 -- the issuer's own files in its config directory
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		key, err := ReadKey(data, PEMIssuer)
		if err != nil {
			return nil, err
		}
		iss, err := orgpki.Open(lines, key, s.Sink)
		if err == nil && name != IssuerKeyFile {
			err = os.Rename(s.Path(name), s.Path(IssuerKeyFile))
		}
		if err == nil {
			return iss, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(append(errs, errors.New("no issuer key that the log names"))...)
}

// WriteCRL keeps der, signed by issuer, as the issuer's newest CRL, and
// its OpenSSH KRL beside it (KRLFile: this machine's ssh RevokedHostKeys).
func (s *Store) WriteCRL(der []byte, issuer *x509.Certificate) error {
	if err := orgfiles.Write(s.Path(CRLFile), der, 0o600); err != nil {
		return err
	}
	return s.writeKRL(der, issuer)
}

func (s *Store) writeKRL(der []byte, issuer *x509.Certificate) error {
	k, err := orgpki.HostKRL(der, issuer)
	if err != nil {
		return err
	}
	return orgfiles.Write(s.Path(KRLFile), k, 0o644) // #nosec G306 -- a KRL is public, read by ssh
}

// KRL is the path of the KRL of the issuer's newest CRL, written first when
// missing (ssh refuses every host when its RevokedHostKeys file is).
func (s *Store) KRL(issuer *x509.Certificate) (string, error) {
	if _, err := os.Stat(s.Path(KRLFile)); err == nil {
		return s.Path(KRLFile), nil
	}
	der, err := s.ReadCRL()
	if err == nil && der == nil {
		err = errors.New("the issuer has signed no CRL yet: run nfltr node or nfltr org serve")
	}
	if err == nil {
		err = s.writeKRL(der, issuer)
	}
	return s.Path(KRLFile), err
}

// ReadCRL is the newest CRL written, nil when none.
func (s *Store) ReadCRL() ([]byte, error) {
	der, err := os.ReadFile(s.Path(CRLFile)) // #nosec G304 -- the issuer's own file
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return der, err
}

// RevokeMachines revokes, in the issuer of directory dir, every name
// whose certificates carry one of the machine ids (an account's revoked
// machines: one revoke there reaches the organisation too), and writes
// the CRL that
// lists them; Serve publishes it. No organisation in dir, or no such
// name: nothing. It returns the names it revoked.
func RevokeMachines(dir string, ids []string, now time.Time) ([]string, error) {
	if !Exists(dir) || len(ids) == 0 {
		return nil, nil
	}
	s, err := Lock(dir)
	if err != nil {
		return nil, err
	}
	defer s.Unlock()
	iss, err := s.Open()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, id := range ids {
		if name := iss.NameOfMachine(id); name != "" {
			if err := iss.Revoke(name, now); err != nil {
				return names, err
			}
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	crl, err := iss.CRL(now)
	if err != nil {
		return names, err
	}
	return names, s.WriteCRL(crl, iss.Cert())
}
