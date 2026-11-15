// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !wasip1

package orgfiles

import (
	"errors"
	"os"
	"syscall"
)

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the directory of the file the caller writes, opened only to fsync it
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func lock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

func tryLock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}
