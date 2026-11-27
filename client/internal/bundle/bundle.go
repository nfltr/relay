// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

// Package bundle is the browser extension's code pin (nfltr
// docs/decisions/browser-peer-2026-11-16.md section 3,
// BIND:browser.bundle): the SHA256SUMS of every file of the extension, and
// the check that a package (what is uploaded to a store, or installed) is
// exactly the release's, no file changed, added or missing.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
)

// SumsFile is the listing's own name, left out of it.
const SumsFile = "SHA256SUMS"

// Sums is the SHA256SUMS listing of every regular file of fsys but
// SumsFile, sorted by path: "<hex>  <path>\n" (sha256sum's format).
func Sums(fsys fs.FS) ([]byte, error) {
	var b bytes.Buffer
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("bundle: %s is not a regular file", path)
		case path == SumsFile:
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%x  %s\n", sha256.Sum256(data), path)
		return nil
	})
	return b.Bytes(), err
}

// ErrMismatch: the package is not the release's bundle.
var ErrMismatch = errors.New("bundle: the package is not the release's")

// Verify checks that fsys holds exactly the files sums lists, with their
// hashes.
func Verify(fsys fs.FS, sums []byte) error {
	got, err := Sums(fsys)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, sums) {
		return fmt.Errorf("%w: its sums\n%s", ErrMismatch, got)
	}
	return nil
}
