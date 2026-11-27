// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package orgenrol

// The keeper's half of the session audit (nfltr
// docs/decisions/service-access-2026-11-25.md "SA5"): the lines of the
// machine's audit log the issuer has not acknowledged go to it sealed
// (orgpki.SealAudit) on the enrol drop box with the machine's signed
// head, every orgaudit.ShipEvery while there are some, the head alone
// every orgaudit.BeatEvery. One process of the machine ships at a time
// (shipLock); where it stands is shipFile.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/nfltr/relay/client/orgaudit"
	"github.com/nfltr/relay/org/internal/orgfiles"
	"github.com/nfltr/relay/org/orgmachine"
	"github.com/nfltr/relay/org/orgpki"
)

const (
	shipLock = "audit.ship.lock"
	shipFile = "audit.sent" // shipped: the log and the bytes of it the issuer acknowledged
	shipMax  = 256 << 10    // bytes of lines in one post
)

type shipped struct {
	Log    string `json:"log"`
	Offset int64  `json:"offset"`
}

// shipAudit ships m's audit lines until ctx ends.
func shipAudit(ctx context.Context, mb Mailbox, m *orgmachine.Machine, wait time.Duration, now func() time.Time, logger *slog.Logger) {
	var beat time.Time // the last post the issuer answered
	for ctx.Err() == nil {
		switch posted, err := shipOnce(ctx, mb, m, now().Sub(beat) >= orgaudit.BeatEvery, wait, now); {
		case errors.Is(err, orgfiles.ErrLocked): // another process of the machine ships
		case err != nil:
			if ctx.Err() == nil {
				logger.Warn("org: the session audit did not reach the issuer (again shortly; the machine keeps every line)", "error", err)
			}
		case posted:
			beat = now()
		}
		t := time.NewTimer(orgaudit.ShipEvery)
		select {
		case <-ctx.Done():
		case <-m.Audited(): // this process wrote a line: ship it now
		case <-t.C:
		}
		t.Stop()
	}
}

// shipOnce posts what is unacknowledged (or, with beat, the head alone)
// and takes the issuer's answer. posted: a post was answered.
func shipOnce(ctx context.Context, mb Mailbox, m *orgmachine.Machine, beat bool, wait time.Duration, now func() time.Time) (posted bool, err error) {
	dir := m.Dir()
	unlock, err := orgfiles.TryLock(filepath.Join(dir, shipLock))
	if err != nil {
		return false, err
	}
	defer unlock()
	var at shipped
	if err := readJSON(filepath.Join(dir, shipFile), &at); err != nil {
		return false, err
	}
	lines, end, err := unshipped(dir, &at)
	if err != nil || len(lines) == 0 && !beat {
		return false, err
	}
	last, err := orgmachine.LastAudit(dir)
	if err != nil || last == nil {
		return false, err
	}
	if len(lines) > 0 {
		last = lines[len(lines)-1]
	}
	lr, err := orgaudit.Parse(last)
	if err != nil {
		return false, err
	}
	cert, key := m.Current()
	head, err := orgaudit.SignHead(orgaudit.Signing{Log: lr.Log, Seq: lr.Seq, Prev: orgaudit.Hash(last), Machine: lr.Machine, Cert: cert, Key: key, At: now()})
	if err != nil {
		return false, err
	}
	sealed, err := orgpki.SealAudit(m.Issuer(), orgpki.AuditBatch{Lines: lines, Head: head})
	if err != nil {
		return false, err
	}
	// A batch's id is its lines (a retry is answered as the first post);
	// a beat's its time.
	id := fmt.Sprintf("audit-%s-%d-%d", lr.Log, at.Offset, end)
	if len(lines) == 0 {
		id = fmt.Sprintf("audit-%s-beat-%d", lr.Log, now().UnixNano())
	}
	a, err := exchange(ctx, mb, m.OrgID(), orgpki.Request{ID: id, Audit: &orgpki.AuditRequest{Sealed: sealed}}, wait)
	if err != nil {
		return false, err
	}
	if a.Audit == nil {
		return false, errors.New("the issuer's answer names no audit position")
	}
	// The issuer took what verified and logged the rest: either way
	// these lines are done (the machine's own copy keeps them).
	at.Log, at.Offset = lr.Log, end
	return true, writeJSON(filepath.Join(dir, shipFile), at)
}

// unshipped are the complete lines of dir's audit log after at (at most
// shipMax bytes) and where they end. A log whose first line is not of
// at's log (the file replaced) is shipped from its start.
func unshipped(dir string, at *shipped) ([][]byte, int64, error) {
	f, err := os.Open(filepath.Join(dir, orgmachine.AuditFile)) // #nosec G304 -- the machine's own directory
	if os.IsNotExist(err) {
		return nil, at.Offset, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	first := make([]byte, 2048)
	n, err := f.ReadAt(first, 0)
	if err != nil && err != io.EOF {
		return nil, 0, err
	}
	if r, err := orgaudit.Parse(first[:max(bytes.IndexByte(first[:n], '\n'), 0)]); err != nil || r.Log != at.Log {
		at.Offset = 0
	}
	buf := make([]byte, shipMax)
	n, err = f.ReadAt(buf, at.Offset)
	if err != nil && err != io.EOF {
		return nil, 0, err
	}
	buf = buf[:bytes.LastIndexByte(buf[:n], '\n')+1]
	var lines [][]byte
	for l := range bytes.Lines(buf) {
		lines = append(lines, bytes.TrimSuffix(l, []byte("\n")))
	}
	return lines, at.Offset + int64(len(buf)), nil
}
