// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package orgfiles is the organisation issuer's packages' own file
// helpers (orgissuer, orgmachine, orgenrol): a file replaced whole, a file
// created once, and an exclusive lock across processes. It is a small copy
// of nfltr's platform atomicfile and filelock, the one duplication the
// issuer's packages accept so that they import nothing of nfltr.
package orgfiles

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path whole with data (perm): written aside, fsynced,
// renamed into place, then its directory fsynced, so a reader sees the old
// file or the new one and a crash after Write returns keeps the new one.
func Write(path string, data []byte, perm os.FileMode) error {
	tmp, err := writeAside(path, data, perm)
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDirOf(path)
}

// WriteNew creates path with data (perm) unless a file is already there,
// which it keeps: a file several processes may make at once. The file
// appears whole or not at all (written aside, fsynced, then linked into
// place); the first writer's content wins.
func WriteNew(path string, data []byte, perm os.FileMode) error {
	tmp, err := writeAside(path, data, perm)
	defer func() { _ = os.Remove(tmp) }()
	if err == nil {
		if err = os.Link(tmp, path); errors.Is(err, os.ErrExist) {
			return nil
		}
	}
	if err != nil {
		return err
	}
	return syncDirOf(path)
}

// writeAside writes data into a new file beside path, fsynced, mode perm.
func writeAside(path string, data []byte, perm os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), perm)
	}
	return f.Name(), err
}

func syncDirOf(path string) error {
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("renamed, directory not synced: %w", err)
	}
	return nil
}

// ErrLocked: TryLock found the lock held (by another process, or another
// descriptor of this one).
var ErrLocked = errors.New("held by another holder")

// Lock creates path if needed and blocks until the caller holds its
// exclusive advisory lock (each call opens its own descriptor, so it also
// excludes goroutines of one process). unlock releases it.
func Lock(path string) (unlock func(), err error) { return acquire(path, lock) }

// TryLock is Lock without waiting: ErrLocked (wrapped) when another holder
// has it.
func TryLock(path string) (unlock func(), err error) { return acquire(path, tryLock) }

func acquire(path string, take func(*os.File) error) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- a lock file of the caller's own directory
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := take(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire lock %s: %w", path, err)
	}
	return func() { _ = unlockFile(f); _ = f.Close() }, nil
}
