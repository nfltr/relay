// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package rpcclient

// The callee's replay record (spec/A2ASession.tla rec; nfltr
// docs/decisions/a2a-at-most-once-restart-2026-11-09.md): every call
// number a callee takes on a session, by a resume or by answering a retry,
// it first appends to a file and syncs it, before the call starts. A
// retry naming a session the callee no longer keeps (a restart, expiry,
// eviction) is refused when the record has its number, so a relay that
// forges unknown cannot make a served call run again, a restart in
// between included.
//
// Layout: dir/<slot>.a2areplay, slot = unix time / a2aReplaySlot; each
// record is session id ‖ call number (8 bytes, big endian). A retry the
// callee answers names a resume taken at most a2aRetryBound ago by either
// clock (a2aSessions.retry), so with clocks less than a2aRetryBound apart
// its record is in the current or the previous slot; older files go.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	a2aReplaySlot   = 2 * a2aRetryBound
	a2aReplaySuffix = ".a2areplay"
)

// a2aReplayRecord is one callee's record in dir. Every process that
// answers as the same agent may share dir: records are whole appends, and
// session ids are the sessions' own (HMAC of their secret).
type a2aReplayRecord struct {
	dir string
	now func() time.Time // tests

	mu   sync.Mutex // held across a take: check, append, sync
	f    *os.File
	slot int64
}

// openA2AReplayRecord makes dir (0700) and checks it takes a record.
func openA2AReplayRecord(dir string) (*a2aReplayRecord, error) {
	if dir == "" {
		return nil, errors.New("rpcclient: an A2A E2EE replay record needs a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil { // nosemgrep: incorrect-default-permission -- the record directory, owner only (0700)
		return nil, fmt.Errorf("rpcclient: A2A E2EE replay record: %w", err)
	}
	r := &a2aReplayRecord{dir: dir}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.file(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *a2aReplayRecord) slotNow() int64 {
	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	return now.Unix() / int64(a2aReplaySlot/time.Second)
}

func (r *a2aReplayRecord) path(slot int64) string {
	return filepath.Join(r.dir, strconv.FormatInt(slot, 10)+a2aReplaySuffix)
}

// file is the current slot's file, opened for appends; moving to a new
// slot removes the files older than the previous one. Under r.mu.
func (r *a2aReplayRecord) file() (*os.File, error) {
	slot := r.slotNow()
	if r.f != nil && slot == r.slot {
		return r.f, nil
	}
	f, err := os.OpenFile(r.path(slot), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: A2A E2EE replay record: %w", err)
	}
	if r.f != nil {
		_ = r.f.Close()
	}
	r.f, r.slot = f, slot
	if names, err := os.ReadDir(r.dir); err == nil {
		for _, e := range names {
			n, ok := strings.CutSuffix(e.Name(), a2aReplaySuffix)
			if s, err := strconv.ParseInt(n, 10, 64); ok && err == nil && s < slot-1 {
				_ = os.Remove(filepath.Join(r.dir, e.Name()))
			}
		}
	}
	return f, nil
}

func a2aReplayEntry(id [a2aSessionIDLen]byte, c uint64) []byte {
	return binary.BigEndian.AppendUint64(append([]byte(nil), id[:]...), c)
}

// write appends c on id and syncs it: when it returns nil, a restart
// keeps it. Under r.mu.
// ponytail: one fsync per resumed call, serialized; group commit if a callee's resume rate needs it.
func (r *a2aReplayRecord) write(id [a2aSessionIDLen]byte, c uint64) error {
	f, err := r.file()
	if err != nil {
		return err
	}
	if _, err := f.Write(a2aReplayEntry(id, c)); err != nil {
		return fmt.Errorf("rpcclient: A2A E2EE replay record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("rpcclient: A2A E2EE replay record: %w", err)
	}
	return nil
}

// has reports whether the current or the previous slot records c on id;
// a file it cannot read counts as having it (refused: at most once). It
// looks for the record at any offset, so a torn record (a crash
// mid-append: its call never started) misaligns nothing after it. Under
// r.mu.
// ponytail: a scan of two files per retry of a session the callee no longer keeps (rare: a restart, expiry); an index if it shows.
func (r *a2aReplayRecord) has(id [a2aSessionIDLen]byte, c uint64) bool {
	want := a2aReplayEntry(id, c)
	slot := r.slotNow()
	for _, s := range []int64{slot - 1, slot} {
		data, err := os.ReadFile(r.path(s)) // #nosec G304 -- this record's own file
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return true
		}
		if bytes.Contains(data, want) {
			return true
		}
	}
	return false
}

// close closes the current file (a later take opens it again).
func (r *a2aReplayRecord) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
}
