// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package pairfile replaces a key file and the certificate file of that key
// as one pair, so that a writer stopped at any step (killed, a power loss,
// a failed write) leaves a pair every reader takes: no user action after a
// crash (spec/pair/MachinePair.tla, lane CERTATOMIC). Each file is replaced
// by one rename (written aside, fsynced, renamed, the directory fsynced);
// the new key goes beside the old one first (<key>.next), then the
// certificate, then the new key is renamed over the old. Read takes
// whichever of the two keys the certificate certifies. Write first
// finishes a swap a stopped writer left (rolls it forward, as a journal's
// recovery does), so it never overwrites the only key the certificate
// certifies. The two files keep their names and formats: a machine
// enrolled before needs no migration. Writers of one pair are serialised
// by the caller (a lock released when its holder dies).
package pairfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Pair is a key file and its certificate file, in one directory.
type Pair struct {
	Key, Cert string
	// Match is nil when cert certifies key, an error wrapped by Mismatch
	// when it certifies another key; any other error (a file that does not
	// parse) fails Read at once.
	Match func(cert, key []byte) error
}

// ErrMismatch: the certificate certifies another key (errors.Is).
var ErrMismatch = errors.New("the certificate certifies another key")

type mismatch struct{ error }

func (m mismatch) Is(t error) bool { return t == ErrMismatch }
func (m mismatch) Unwrap() error   { return m.error }

// Mismatch is err (its text unchanged) as a Match answer that the
// certificate certifies another key.
func Mismatch(err error) error { return mismatch{err} }

// Next is the new key's file while a replacement runs.
func (p Pair) Next() string { return p.Key + ".next" }

// wait bounds Read against a writer that replaces the pair while it reads
// (the certificate read before a whole replacement, the key after it).
const wait = 5 * time.Second

// Read is the certificate and the key it certifies: the certificate, then
// the new key, then the key (MachinePair.tla RCert, RNext, RKey), read
// again while neither matches, at most wait.
func (p Pair) Read() (cert, key []byte, err error) {
	for deadline := time.Now().Add(wait); ; time.Sleep(10 * time.Millisecond) {
		if cert, err = os.ReadFile(p.Cert); err != nil {
			return nil, nil, err
		}
		if key, err = readKey(p.Next()); err == nil && p.Match(cert, key) == nil {
			trace(p, "read", "next")
			return cert, key, nil
		}
		if key, err = readKey(p.Key); err != nil {
			return nil, nil, err
		}
		if err = p.Match(cert, key); err == nil {
			trace(p, "read", "key")
			return cert, key, nil
		}
		if !errors.Is(err, ErrMismatch) || time.Now().After(deadline) {
			return nil, nil, err
		}
	}
}

// Write replaces the pair with cert and key (0600 each). The caller holds
// the pair's lock.
func (p Pair) Write(cert, key []byte) error { return p.WriteFirst(Steps, cert, key) }

// Steps is the number of Write's steps (MachinePair.tla Recover,
// WriteNext, WriteCert, Swap).
const Steps = 4

// WriteFirst is Write stopped after its first n steps, the files as a
// writer killed there leaves them: for crash tests.
func (p Pair) WriteFirst(n int, cert, key []byte) error {
	trace(p, "lock", "")
	for _, s := range p.steps(cert, key)[:n] {
		if err := s.do(); err != nil {
			return err
		}
		trace(p, s.name, "")
	}
	return nil
}

type step struct {
	name string
	do   func() error
}

// steps are Write's, in order (MachinePair.tla Recover, WriteNext,
// WriteCert, Swap); a test stops after any of them.
func (p Pair) steps(cert, key []byte) []step {
	return []step{
		{"recover", p.recover},
		{"next", func() error { return write(p.Next(), key) }},
		{"cert", func() error { return write(p.Cert, cert) }},
		{"swap", func() error { return rename(p.Next(), p.Key) }},
	}
}

// recover finishes a stopped writer's swap: the certificate certifies the
// new key and not the key.
func (p Pair) recover() error {
	cert, err := os.ReadFile(p.Cert)
	if errors.Is(err, os.ErrNotExist) {
		return nil // nothing enrolled yet
	}
	if err != nil {
		return err
	}
	next, err := readKey(p.Next())
	if err != nil || p.Match(cert, next) != nil {
		return nil // none, or a stale one Write replaces
	}
	if key, err := readKey(p.Key); err == nil && p.Match(cert, key) == nil {
		return nil
	}
	return rename(p.Next(), p.Key)
}

// readKey reads a key file other users cannot read. Windows reports every
// writable file as 0666 whatever its ACL says, so there the mode is not
// checked (machinecert.LoadKey's rule).
func readKey(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: mode %v, want 0600", path, st.Mode().Perm())
	}
	return os.ReadFile(path) // #nosec G304 -- a file of the machine's own directory
}

// write replaces path whole with data, 0600: written aside, fsynced,
// renamed, the directory fsynced.
func write(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	err = tmp.Chmod(0o600)
	if err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return rename(tmp.Name(), path)
}

// rename renames from over to and fsyncs their directory, so a power loss
// keeps the renames in order.
func rename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	// ponytail: Windows cannot open a directory for Sync (NTFS journals the
	// rename), so its error is not one.
	if d, err := os.Open(filepath.Dir(to)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
