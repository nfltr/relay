// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgaudit

// The log's file helpers: a file replaced whole and an exclusive lock
// across processes. A copy of relay org's internal orgfiles (itself a
// copy of nfltr's atomicfile and filelock): the client module cannot
// import it, and the two serving identities share one log.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// errLocked: tryLockFile found the lock held (by another process, or
// another descriptor of this one).
var errLocked = errors.New("held by another holder")

// writeFile replaces path whole with data (perm): written aside, fsynced,
// renamed into place, then its directory fsynced.
func writeFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, perm)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// lockFile creates path if needed and blocks until the caller holds its
// exclusive advisory lock (each call its own descriptor, so it also
// excludes goroutines of one process).
func lockFile(path string) (unlock func(), err error) { return acquire(path, lock) }

// tryLockFile is lockFile without waiting: errLocked (wrapped) when held.
func tryLockFile(path string) (unlock func(), err error) { return acquire(path, tryLock) }

func acquire(path string, take func(*os.File) error) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- a lock file of the machine's own directory
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := take(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire lock %s: %w", path, err)
	}
	return func() { _ = unlockFile(f); _ = f.Close() }, nil
}
